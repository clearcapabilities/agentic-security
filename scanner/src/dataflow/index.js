// Layer 2 entry point.
import { runTaintEngine } from './engine.js';
import { CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize } from './catalog.js';
import { applyPathFeasibility } from './path-feasibility.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';
import { rhsReachableFunctions, shouldAnalyzeUnderRhs } from './tabulation.js';
import { annotateBackwardSlices } from './backward.js';

export function runDeepAnalysis(perFileIR, callGraph, opts = {}) {
  // Path-feasibility pass over every function before the taint walk.
  let totalPruned = 0;
  for (const fn of callGraph.functions.values()) {
    const r = applyPathFeasibility(fn);
    totalPruned += r.pruned;
  }
  // P2.1 — RHS-lite reachability slice. When AGENTIC_SECURITY_RHS=1 the
  // engine narrows analysis to sink-reachable functions. Default OFF
  // because it changes the finding-set composition.
  if (process.env.AGENTIC_SECURITY_RHS === '1') {
    const ctx = rhsReachableFunctions(perFileIR, callGraph);
    if (ctx.reachable) {
      opts = { ...opts, _rhsReachable: ctx.reachable, _rhsCheck: shouldAnalyzeUnderRhs };
    }
  }
  let findings = runTaintEngine(perFileIR, callGraph, opts);
  for (const f of findings) f._pathFeasibilityPruned = totalPruned;
  // P1.4 — backward slice (opt-in via AGENTIC_SECURITY_BACKWARD_SLICE=1).
  if (process.env.AGENTIC_SECURITY_BACKWARD_SLICE === '1') {
    findings = annotateBackwardSlices(findings, perFileIR, callGraph);
  }
  return findings;
}

export { runTaintEngine, CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize, applyPathFeasibility, SummaryCache, entryStateFromCall, rhsReachableFunctions, shouldAnalyzeUnderRhs, annotateBackwardSlices };
