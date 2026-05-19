// Higher-order function / callback taint propagation (P1.3).
//
// The base engine drops taint at the `.map` boundary today:
//
//   const data = req.body.items;            // data IS tainted
//   const cleaned = data.map(x => x.trim()); // x is the array element;
//                                            // the engine should taint
//                                            // the inner `x`, and the
//                                            // returned `.trim()` value.
//
// This module recognizes a fixed set of canonical higher-order shapes and
// returns the callback's parameter-taint contribution. It does NOT do full
// closure analysis; it does the high-value 80% case:
//
//   Array methods:     map / forEach / filter / reduce / flatMap / find /
//                      findIndex / some / every / sort / flat
//   Promise methods:   then / catch / finally
//   Promise statics:   Promise.all / Promise.allSettled / Promise.race
//   Iterables:         for...of body (handled by IR loop-header already)
//   RxJS-style:        subscribe / pipe (best-effort)
//
// Public API:
//   higherOrderTaintFlow(node, receiverTainted)
//     → { callbackTaintsFirstArg: bool, returnIsTainted: bool }
//
// Returns null when the call isn't a recognized higher-order shape.

const _ARRAY_FIRST_ARG_PROPAGATING = new Set([
  'map', 'forEach', 'filter', 'flatMap', 'find', 'findIndex', 'findLast',
  'findLastIndex', 'some', 'every', 'reduce', 'reduceRight', 'sort',
  'partition',  // lodash + RxJS
]);

const _PROMISE_INSTANCE_METHODS = new Set([
  'then', 'catch', 'finally',
]);

const _PROMISE_STATIC_METHODS = new Set([
  'all', 'allSettled', 'race', 'any',
]);

const _RX_OPERATORS = new Set([
  'subscribe', 'pipe', 'tap', 'switchMap', 'mergeMap', 'concatMap',
  'exhaustMap', 'flatMap',
]);

/**
 * Inspect a call node from the IR. If it's a recognized higher-order
 * pattern, return the analysis result. Otherwise return null.
 *
 *   node:               IR call node ({ kind:'call', callee: string-or-expr, args })
 *   receiverTainted:    bool — is the receiver (e.g. the array) tainted?
 */
export function higherOrderTaintFlow(node, receiverTainted) {
  if (!node || node.kind !== 'call') return null;
  const callee = node.callee;
  if (!callee || typeof callee !== 'string') return null;

  const lastDot = callee.lastIndexOf('.');
  const method = lastDot >= 0 ? callee.slice(lastDot + 1) : callee;
  const receiver = lastDot >= 0 ? callee.slice(0, lastDot) : null;

  // Array iteration methods — callback's first arg = element of receiver.
  if (receiver && _ARRAY_FIRST_ARG_PROPAGATING.has(method)) {
    return {
      kind: 'array-iter',
      callbackArgIndex: 0,                          // first arg is the callback
      taintsCallbackParam: receiverTainted ? 0 : -1, // first callback param = element
      // .map / .filter / .flatMap return arrays; their elements inherit
      // taint from the callback's return — modeled here as "returnIsTainted
      // iff the receiver array was tainted."
      returnIsTainted: receiverTainted,
    };
  }

  // Promise instance methods.
  if (receiver && _PROMISE_INSTANCE_METHODS.has(method)) {
    return {
      kind: 'promise-then',
      callbackArgIndex: 0,
      taintsCallbackParam: receiverTainted ? 0 : -1, // resolved value goes to first callback param
      returnIsTainted: receiverTainted,
    };
  }

  // Promise.all / Promise.race — the resolved value is the receiver array.
  if (callee.startsWith('Promise.') && _PROMISE_STATIC_METHODS.has(method)) {
    // Args is an array literal of promises. Taint propagates element-wise;
    // we conservatively say if any arg is tainted, the resolved value is.
    const anyArgTainted = (node.args || []).some(a =>
      a && a.kind === 'array' && (a.elements || []).some(e => e && (e.kind === 'ident' || e.kind === 'member'))
    );
    return {
      kind: 'promise-static',
      callbackArgIndex: -1,                          // no callback
      taintsCallbackParam: -1,
      returnIsTainted: anyArgTainted,                // best-effort
    };
  }

  // RxJS-style operators.
  if (receiver && _RX_OPERATORS.has(method)) {
    return {
      kind: 'rx-operator',
      callbackArgIndex: 0,
      taintsCallbackParam: receiverTainted ? 0 : -1,
      returnIsTainted: receiverTainted,
    };
  }

  return null;
}

/**
 * Check if a call's callee references a function literal that we can
 * identify (for resolved propagation).
 *
 *   .map(fn)             where fn was previously assigned a function value
 *   .forEach(x => ...)   inline arrow — IR may emit this as a 'function-value' expr
 */
export function calleeIsResolvableCallback(arg) {
  if (!arg) return null;
  // Inline arrow / function expression — IR shape may carry a callbackQid.
  if (arg.kind === 'function-value' && arg.qid) return arg.qid;
  if (arg.kind === 'ident') return arg.name;
  return null;
}

export { _ARRAY_FIRST_ARG_PROPAGATING, _PROMISE_INSTANCE_METHODS, _PROMISE_STATIC_METHODS, _RX_OPERATORS };
