// Backward taint slicing (P1.4).
//
// Forward analysis answers: "given these sources, what flows reach the sinks?"
// Backward slicing answers: "given this sink, walk back along def-use to
// find the source(s)." The two combined give precise source→sink paths for
// every emitted finding — the "show me the work" explainability layer.
//
// Algorithm (intraprocedural for v1):
//
//   slice(fn, sinkNode, sinkArgPath):
//     work = [{ node: sinkNode, path: sinkArgPath }]
//     visited = set
//     trail = []
//     while work non-empty:
//       n = work.pop()
//       if visited.has(n.node + ':' + n.path): continue
//       visited.add(...)
//       if n.node is 'assign' and target subsumes n.path:
//         trail.push(n)
//         enqueue every read in n.node.source as a new query
//       follow CFG predecessor edges and continue
//     return trail (oldest first)
//
// We use the IR CFG's `succ` arrays — predecessors are not directly stored
// but we precompute the reverse edges for each function on demand.
//
// Interprocedural: when the sink's argument is bound to a function parameter,
// we ascend to caller(s) by consulting the call graph. v1 visits up to 5
// callers (BFS-bounded) to keep the slicer fast.

import { accessPathOf, pathIsCoveredByPrefix } from './access-paths.js';

const SLICE_BUDGET_NODES = 200;
const SLICE_BUDGET_CALLERS = 5;

function _reverseEdges(cfg) {
  const rev = new Map();
  if (!cfg || !cfg.nodes) return rev;
  for (const id of Object.keys(cfg.nodes)) {
    const node = cfg.nodes[id];
    for (const s of (node?.succ || [])) {
      if (!rev.has(s)) rev.set(s, []);
      rev.get(s).push(id);
    }
  }
  return rev;
}

/**
 * Build a backward slice from a finding's sink site to its source(s).
 *
 *   fn:        the function the sink lives in
 *   sinkNode:  the IR node where the sink fires
 *   sinkArgPath: the access path of the tainted argument (string)
 *
 * Returns an ordered list of trace steps (source-first):
 *   [
 *     { line, kind: 'source', label, varName, path },
 *     { line, kind: 'assign', from, to, path },
 *     { line, kind: 'call',   callee, argPath, path },
 *     { line, kind: 'sink',   callee, argIndex, path },
 *   ]
 */
export function sliceBackward(fn, sinkNode, sinkArgPath) {
  const out = [];
  if (!fn || !sinkNode) return out;
  const cfg = fn.cfg;
  if (!cfg || !cfg.nodes) return out;
  const rev = _reverseEdges(cfg);

  // Map node-id to itself lookup for nodes in this CFG.
  const nodes = cfg.nodes;

  // We don't directly know the node-id of `sinkNode`; the caller passes
  // a reference. Recover it by linear search (CFGs are small per fn).
  let sinkNid = null;
  for (const id of Object.keys(nodes)) {
    if (nodes[id] === sinkNode) { sinkNid = id; break; }
  }
  if (!sinkNid) return out;

  out.push({
    line: sinkNode.line || 0,
    kind: 'sink',
    callee: sinkNode.callee || null,
    path: sinkArgPath,
  });

  const work = [{ nid: sinkNid, queryPath: sinkArgPath }];
  const visited = new Set();
  let visitedCount = 0;

  while (work.length) {
    if (++visitedCount > SLICE_BUDGET_NODES) break;
    const { nid, queryPath } = work.shift();
    const key = `${nid}::${queryPath}`;
    if (visited.has(key)) continue;
    visited.add(key);

    const node = nodes[nid];
    if (!node) continue;

    // The query path matches an assignment target? Record the def + chase RHS.
    if (node.kind === 'assign' && typeof node.target === 'string' && pathIsCoveredByPrefix(queryPath, node.target)) {
      const srcAp = accessPathOf(node.source);
      out.push({
        line: node.line || 0,
        kind: 'assign',
        to: node.target,
        from: srcAp,
        path: queryPath,
      });
      // Switch the query to the RHS access path (if any). If the source
      // itself is a catalog source (req.body, etc.), mark it as the
      // origin step.
      if (srcAp) {
        // Heuristic source detection without re-importing catalog —
        // anything that starts with a common source prefix.
        if (/^req\.(?:body|query|params|headers|cookies)|process\.env|window\.location|document\.URL/.test(srcAp)) {
          out.push({
            line: node.line || 0,
            kind: 'source',
            label: srcAp,
            path: queryPath,
          });
          continue;
        }
        // Otherwise, follow the def of the new query path upstream.
        work.push({ nid, queryPath: srcAp });
      }
    }

    // Walk predecessors regardless — defs can be on prior nodes.
    for (const p of (rev.get(nid) || [])) {
      work.push({ nid: p, queryPath });
    }
  }

  // Reverse so the trace reads source-first.
  return out.reverse();
}

/**
 * Helper: annotate every finding in a list with its backward slice.
 *
 *   findings: produced by the engine, expected to carry `_funcQid` and `line`.
 *   perFileIR / callGraph: same shape the dataflow engine consumes.
 */
export function annotateBackwardSlices(findings, perFileIR, callGraph) {
  if (!Array.isArray(findings)) return findings;
  // Build a qid → fn map for O(1) lookup.
  const fnByQid = new Map();
  if (callGraph && callGraph.functions) {
    for (const fn of callGraph.functions.values()) fnByQid.set(fn.qid, fn);
  }
  for (const f of findings) {
    if (!f || !f._funcQid) continue;
    const fn = fnByQid.get(f._funcQid);
    if (!fn) continue;
    // Find the sink node in fn by line + callee match.
    let sinkNode = null;
    for (const nid of Object.keys(fn.cfg?.nodes || {})) {
      const n = fn.cfg.nodes[nid];
      if (!n || n.kind !== 'call') continue;
      if (n.line === f.line && n.callee === f.callee) { sinkNode = n; break; }
    }
    if (!sinkNode) continue;
    // The tainted arg path — derive from the tainted argument's expression.
    const taintedArg = (sinkNode.args || [])[f.argIndex];
    const argPath = accessPathOf(taintedArg) || `arg[${f.argIndex}]`;
    const slice = sliceBackward(fn, sinkNode, argPath);
    if (slice && slice.length) {
      f.backwardSlice = slice;
      f.pathSteps = (f.pathSteps || []).concat(slice.map(s => ({
        type: s.kind,
        label: s.label || s.callee || s.path || '',
        line: s.line,
      })));
    }
  }
  return findings;
}
