// Implicit-flow detection (P1.5).
//
// Today the engine tracks EXPLICIT taint — values flow into sinks. Implicit
// flow tracks CONTROL-DEPENDENCE: when a branch's condition is tainted, any
// variable assigned in that branch carries a SECONDARY taint at lower
// confidence (0.5 by default).
//
// Canonical motivating pattern:
//
//   if (req.body.role === 'admin') {
//     isAdmin = true;
//   }
//   if (isAdmin) callDangerous();
//
// The explicit-flow engine never sees taint flow into `isAdmin` — the
// dependence is control-only. Implicit-flow analysis adds `isAdmin` to a
// SHADOW state with confidence 0.5 whenever it's mutated inside a
// tainted-conditional branch.
//
// Over-approximation: implicit flow is famously noisy (sneaks into pure
// branches that don't actually leak info). So this analysis is OPT-IN
// only — gated by AGENTIC_SECURITY_IMPLICIT_FLOW=1 — and findings emitted
// carry an explicit `implicit:true` flag + capped confidence at 0.55.
//
// Public API:
//   isImplicitFlowEnabled()           → bool from env
//   buildImplicitContext(cfg, taintState)
//     → Map<nodeId, { tainted: bool, conditionLabel: string }>
//   mutationsInTaintedBranch(node, ctx)
//     → array of variable names that get assigned in a tainted branch
//   applyImplicitFlow(state, mutatedVars, conditionLabel)
//     → new state with the implicit-tainted vars added at confidence 0.5

import { addPath } from './access-paths.js';

export function isImplicitFlowEnabled() {
  return process.env.AGENTIC_SECURITY_IMPLICIT_FLOW === '1';
}

/**
 * Compute, for each CFG node, whether it's "inside" a tainted-condition
 * branch and what condition tainted it. Returns Map<nodeId, ctx>.
 *
 *   cfg:           the function CFG
 *   exprTaint:     callback (expr) -> bool, using the current taint state
 *
 * Heuristic: walk forward from entry, and when we hit an `if` whose
 * condition is tainted, mark all nodes reachable from the consequent (and,
 * if present, the alternate) until we exit those branches.
 */
export function buildImplicitContext(cfg, exprTaint) {
  const ctxByNid = new Map();
  if (!cfg || !cfg.nodes) return ctxByNid;
  // Walk forward; track "depth" of how many tainted-branches we're nested in.
  const visited = new Set();
  const stack = [{ nid: cfg.entry, depth: 0, label: null }];
  while (stack.length) {
    const { nid, depth, label } = stack.pop();
    if (visited.has(nid)) continue;
    visited.add(nid);
    if (depth > 0) ctxByNid.set(nid, { tainted: true, conditionLabel: label });
    const n = cfg.nodes[nid];
    if (!n) continue;
    if (n.kind === 'if' && n.cond && exprTaint(n.cond)) {
      // Push the consequent at depth+1. We don't have a separate alternate
      // edge in this v1 IR — `succ` carries both. v2 should add `then`/`else`
      // distinguishing edges.
      for (const s of (n.succ || [])) {
        stack.push({ nid: s, depth: depth + 1, label: _formatCondLabel(n.cond) });
      }
    } else {
      for (const s of (n.succ || [])) {
        stack.push({ nid: s, depth, label });
      }
    }
  }
  return ctxByNid;
}

function _formatCondLabel(cond) {
  if (!cond) return '?';
  if (cond.kind === 'ident') return cond.name;
  if (cond.kind === 'member') return `${_formatCondLabel(cond.object)}.${cond.prop}`;
  if (cond.kind === 'binary') return `${_formatCondLabel(cond.left)} ${cond.op} ${_formatCondLabel(cond.right)}`;
  if (cond.kind === 'literal') return JSON.stringify(cond.value);
  return cond.kind || '?';
}

/**
 * Given an `assign` node, return the target name if the assignment happens
 * inside a tainted branch.
 */
export function implicitAssignTarget(node, ctx) {
  if (!node || node.kind !== 'assign') return null;
  if (!ctx || !ctx.tainted) return null;
  if (typeof node.target !== 'string') return null;
  return node.target;
}

/**
 * Add `varName` to `state` with an `implicit-` marker prefix so consumers
 * can distinguish primary taint from implicit (lower-confidence) taint.
 *
 * Convention: implicit taint markers look like `implicit:<varName>` in the
 * state set. Engine sink-checks consult both the primary path AND any
 * `implicit:<...>` paths when emitting findings.
 */
export function markImplicitTaint(state, varName) {
  if (!varName || typeof varName !== 'string') return state;
  return addPath(state, `implicit:${varName}`);
}

/**
 * Helper: produce an implicit-flow finding from an assign-in-tainted-branch
 * event. Used by the engine when a sink later consumes an implicit-tainted
 * variable.
 */
export function createImplicitFinding(node, conditionLabel) {
  return {
    kind: 'taint',
    implicit: true,
    confidence: 0.5,
    vuln: `Implicit flow — variable mutated inside tainted-conditional branch (condition: ${conditionLabel || '?'})`,
    severity: 'medium',
    cwe: 'CWE-200',
    line: node?.line || 0,
    remediation: 'Verify that the conditional branch does not let user-controlled state escape into privileged paths. Implicit-flow findings are noisier than explicit-flow; review with elevated scrutiny.',
  };
}
