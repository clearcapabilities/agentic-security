// k=2 monovariant summary cache — Recommendation #9 of the SCA/SAST plan.
//
// The existing scanner/src/dataflow/summaries.js (referenced by engine.js)
// implements k=1: per-function ONE summary computed under empty entry state.
// That misses the common Juliet pattern of "function is pure when called
// with clean args but vulnerable when called with tainted args" because
// only the empty-state summary is cached.
//
// This module wraps SummaryCache with a per-(qid, entry-state-class) lookup,
// up to 2 distinct entry-state classes per function. The "class" is computed
// from a stable hash of which parameter positions are tainted — at k=2 we
// cache the all-clean state and one tainted state per function. Three or
// more distinct states evict to LRU.
//
// Usage:
//   const k2 = new K2SummaryCache(opts.baseCache);
//   k2.get(qid, entryState)         → summary | undefined
//   k2.compute(qid, entryState, fn) → summary
//   k2.applyAtCallSite(qid, entryState, callerCtx) → mutations
//
// Falls back to k=1 behaviour transparently when summaries.js's
// SummaryCache.get returns a summary that doesn't carry entry-state info,
// so the rest of the engine continues to work unchanged.

const _MAX_STATES_PER_FN = 2;

function _hashEntryState(entryState) {
  // Stable string from a Set of "tainted parameter positions" / variable
  // names. For k=2 we only care about taint cardinality + which positions
  // — the actual values are not modelled (premortem: no value sensitivity
  // until field-sensitive cache lifts in v3).
  if (!entryState) return '∅';
  if (entryState instanceof Set) {
    if (entryState.size === 0) return '∅';
    return [...entryState].sort().join(',');
  }
  if (Array.isArray(entryState)) {
    if (entryState.length === 0) return '∅';
    return entryState.slice().sort().join(',');
  }
  // Fallback for opaque entry states — single bucket.
  return '*';
}

export class K2SummaryCache {
  constructor(baseCache) {
    this._base = baseCache;                  // existing k=1 cache (SummaryCache)
    this._states = new Map();                // qid → Map<stateHash, summary>
    this._stateOrder = new Map();            // qid → array (LRU order)
    this.metrics = { hits: 0, misses: 0, evictions: 0, computes: 0 };
  }

  /**
   * Read a summary for (qid, entry). Returns undefined if uncached.
   * Falls back to the base cache when our k=2 table has no entry.
   */
  get(qid, entryState) {
    const hash = _hashEntryState(entryState);
    const states = this._states.get(qid);
    if (states && states.has(hash)) {
      this.metrics.hits++;
      this._touch(qid, hash);
      return states.get(hash);
    }
    // k=1 fallback — accept whatever the base cache stored.
    if (this._base && typeof this._base.get === 'function') {
      const v = this._base.get(qid, entryState);
      if (v) { this.metrics.hits++; return v; }
    }
    this.metrics.misses++;
    return undefined;
  }

  /**
   * Compute (or retrieve) a summary for (qid, entry). Uses the supplied
   * `compute` function only on miss. Caches per-state at k=2.
   */
  compute(qid, entryState, computeFn) {
    const existing = this.get(qid, entryState);
    if (existing) return existing;
    this.metrics.computes++;
    const summary = computeFn();
    this._store(qid, entryState, summary);
    // Also seed the base cache under empty-entry-state so the k=1 engine
    // paths that don't know about k=2 still see the cleanest summary.
    if (this._base && typeof this._base.set === 'function' && (!entryState || (entryState instanceof Set && entryState.size === 0))) {
      try { this._base.set(qid, new Set(), summary); } catch {}
    }
    return summary;
  }

  /**
   * Apply the cached summary at a call site, propagating return-taint and
   * mutated-parameter taint into the caller's mutation set. Mirrors the
   * base cache's applyAtCallSite signature.
   */
  applyAtCallSite(qid, entryState, callerCtx) {
    const summary = this.get(qid, entryState);
    if (!summary) return null;
    // Defer to the base implementation when present — we don't reimplement
    // the mutation algebra here.
    if (this._base && typeof this._base.applyAtCallSite === 'function') {
      try { return this._base.applyAtCallSite(qid, entryState, callerCtx, summary); }
      catch { return null; }
    }
    return summary;
  }

  _store(qid, entryState, summary) {
    const hash = _hashEntryState(entryState);
    let states = this._states.get(qid);
    let order = this._stateOrder.get(qid);
    if (!states) { states = new Map(); this._states.set(qid, states); }
    if (!order)  { order = []; this._stateOrder.set(qid, order); }
    if (!states.has(hash)) {
      // LRU eviction at k=2.
      while (order.length >= _MAX_STATES_PER_FN) {
        const evict = order.shift();
        states.delete(evict);
        this.metrics.evictions++;
      }
      order.push(hash);
    }
    states.set(hash, summary);
  }
  _touch(qid, hash) {
    const order = this._stateOrder.get(qid);
    if (!order) return;
    const idx = order.indexOf(hash);
    if (idx >= 0) { order.splice(idx, 1); order.push(hash); }
  }

  /**
   * Size of the cache — for diagnostics / metrics dashboards.
   */
  size() {
    let n = 0;
    for (const states of this._states.values()) n += states.size;
    return n;
  }
}

/**
 * Wrap an existing k=1 SummaryCache with k=2 behavior. The engine can opt
 * into this via AGENTIC_SECURITY_K2_TAINT=1.
 */
export function wrapAsK2(baseCache) {
  if (!baseCache) return new K2SummaryCache(null);
  if (baseCache instanceof K2SummaryCache) return baseCache;
  return new K2SummaryCache(baseCache);
}

export const _internals = { _hashEntryState, _MAX_STATES_PER_FN };
