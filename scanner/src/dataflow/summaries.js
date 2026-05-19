// Function-summary cache for context-sensitive interprocedural taint.
//
// PRD §6.2: "k-CFA configurable per analysis." This module implements the
// k=1 monovariant version — each function gets ONE summary per distinct
// entry-taint-state, cached by hash. Higher k = exponential blowup we don't
// pay yet.
//
// A summary captures, given a set of tainted parameter names at function
// entry, what the function does:
//   - which return value(s) are tainted
//   - which call-site arguments get mutated to tainted (by-reference)
//   - which global / module variables get tainted
//   - which findings emit
//
// The taint engine (engine.js) consults the summary cache before re-analyzing
// a callee. Cache key = `${qid}::${sorted-taint-state}`. Cache hits are O(1).
//
// Limitations:
//   - Field sensitivity is at the parameter granularity only (not arbitrary
//     access paths). `f(obj)` with obj.foo tainted is treated the same as
//     obj.bar tainted.
//   - No higher-order tracking — callbacks passed as args aren't analyzed.
//   - Recursion: when we'd recurse into a function already on the analysis
//     stack, we return the bottom summary (no-taint) and rely on fixed-point
//     iteration. With k=1 this converges in ≤2 iterations for typical code.

import * as crypto from 'node:crypto';
import { canonicalize as canonicalizeAccessSet } from './access-paths.js';

function _hashState(taintedParams) {
  if (!taintedParams || taintedParams.size === 0) return 'empty';
  // P1.1: canonicalize the access-path lattice before hashing so equivalent
  // states (e.g. {"x", "x.y"} and {"x"}) produce the same cache key.
  const canon = canonicalizeAccessSet(taintedParams);
  const sorted = [...canon].sort().join('|');
  return crypto.createHash('sha256').update(sorted).digest('hex').slice(0, 12);
}

export class SummaryCache {
  constructor() {
    this._cache = new Map(); // qid::hash → summary
    this._stack = new Set(); // qids currently being analyzed (recursion guard)
    this._iter = 0;
    this._maxIter = 5000;
  }

  _key(qid, taintedParams) {
    return `${qid}::${_hashState(taintedParams)}`;
  }

  get(qid, taintedParams) {
    return this._cache.get(this._key(qid, taintedParams));
  }

  set(qid, taintedParams, summary) {
    this._cache.set(this._key(qid, taintedParams), summary);
  }

  has(qid, taintedParams) {
    return this._cache.has(this._key(qid, taintedParams));
  }

  // Compute the summary for a function (or return cached). The `analyze`
  // callback is the per-function walker that returns
  //   { returnTainted, mutatedParams: Set, taintedGlobals: Set, findings: [] }
  compute(qid, taintedParams, analyze) {
    const k = this._key(qid, taintedParams);
    if (this._cache.has(k)) return this._cache.get(k);
    if (this._stack.has(qid)) {
      // Recursion — return bottom summary; fixed-point iter will refine.
      return { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [], _recursive: true };
    }
    if (++this._iter > this._maxIter) {
      return { returnTainted: false, mutatedParams: new Set(), taintedGlobals: new Set(), findings: [], _budgetExceeded: true };
    }
    this._stack.add(qid);
    try {
      const summary = analyze(qid, taintedParams);
      this._cache.set(k, summary);
      return summary;
    } finally {
      this._stack.delete(qid);
    }
  }

  // Helper: apply a summary to a caller's taint state given the call site's
  // argument bindings. Returns { calleeReturnTainted, mutated: Set of caller-side
  // var names that should become tainted because the callee mutated them }.
  applyAtCallSite(summary, paramNames, callArgs, callerTaintedVars) {
    if (!summary) return { returnTainted: false, mutated: new Set() };
    const mutated = new Set();
    if (summary.mutatedParams && summary.mutatedParams.size) {
      // Map each mutated parameter position back to the caller-side argument name.
      for (const paramName of summary.mutatedParams) {
        const idx = paramNames.indexOf(paramName);
        if (idx < 0) continue;
        const arg = callArgs[idx];
        if (arg && arg.kind === 'ident') mutated.add(arg.name);
      }
    }
    return { returnTainted: !!summary.returnTainted, mutated };
  }

  size() { return this._cache.size; }
  clear() { this._cache.clear(); this._iter = 0; }
}

// Build the entry-taint-state for a callee from a call site:
//   given the callee's param names + the caller's tainted-var set + the
//   call args, return a Set of param names that are tainted at entry.
export function entryStateFromCall(paramNames, callArgs, callerTaintedVars) {
  const out = new Set();
  if (!Array.isArray(paramNames) || !Array.isArray(callArgs)) return out;
  for (let i = 0; i < paramNames.length && i < callArgs.length; i++) {
    const arg = callArgs[i];
    if (!arg) continue;
    if (arg.kind === 'ident' && callerTaintedVars.has(arg.name)) {
      out.add(paramNames[i]);
    } else if (arg.kind === 'member' && arg.object?.kind === 'ident') {
      const base = arg.object.name;
      if (callerTaintedVars.has(base) || callerTaintedVars.has(`${base}.${arg.prop}`)) {
        out.add(paramNames[i]);
      }
    }
  }
  return out;
}
