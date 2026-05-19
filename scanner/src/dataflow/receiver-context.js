// Receiver / object-sensitivity context (P1.2).
//
// Today the engine summary cache keys per-function as `(qid, taint-state)`.
// That conflates calls of the same method on different receivers:
//
//   this.userRepo.save(taintedInput)    // a sink (writes user data)
//   this.logger.save(taintedInput)      // NOT a sink (logs are not user data)
//
// Both calls hit the same `save()` summary today, so the engine either
// over-fires (treats logger.save as a sink) or under-fires (misses
// userRepo.save). Receiver-sensitivity adds a third key dimension: the
// inferred class of the receiver.
//
// This module is a thin helper that:
//   1. extracts the receiver-type hint at a call site (using CHA), and
//   2. mixes it into the summary cache key for the callee
//
// The actual engine integration (using these helpers) lives in engine.js.

import * as crypto from 'node:crypto';
import { classOfVar } from '../ir/class-hierarchy.js';

/**
 * Return the receiver-type label for a call expression, or null if
 * we have no type information.
 *
 *   foo.bar()                                 -> typeOfVar(foo) or 'foo'
 *   this.userRepo.save(x)                     -> 'UserRepo' (heuristic from CHA)
 *   bareIdentCall(x)                          -> null
 */
export function receiverTypeAtCall(node, fn, file, cha) {
  if (!node || node.kind !== 'call') return null;
  const callee = node.callee;
  if (!callee || typeof callee !== 'string') return null;
  // String form like "this.userRepo.save" or "userRepo.save"
  const parts = callee.split('.');
  if (parts.length < 2) return null;            // bareIdentCall — no receiver
  // The receiver chain is parts[0..parts.length-2]. We try to type the
  // outermost identifier first; if it's `this` we look at the field name.
  if (parts[0] === 'this') {
    // For `this.userRepo.save`, the receiver type hint is the FIELD name —
    // we conventionally PascalCase it ("UserRepo"). v1 heuristic only.
    if (parts.length >= 3) {
      const fieldName = parts[1];
      return fieldName.charAt(0).toUpperCase() + fieldName.slice(1);
    }
    return 'this';
  }
  // Try to resolve `foo.save` — type of `foo` from CHA.
  const inferred = classOfVar(cha, file, fn?.qid, parts[0]);
  if (inferred) return inferred;
  // Fall back to the LHS identifier name as a soft label.
  return parts[0];
}

/**
 * Compute a stable hash for a receiver type — used as part of the
 * extended summary cache key.
 */
export function hashReceiverType(receiverType) {
  if (!receiverType) return 'no-recv';
  return crypto.createHash('sha256').update(String(receiverType)).digest('hex').slice(0, 8);
}

/**
 * Extend an existing cache key with a receiver-type dimension.
 *
 *   priorKey = "<qid>::<state-hash>"
 *   newKey   = "<qid>::<state-hash>::<recv-hash>"
 *
 * Backwards-compatible: when receiverType is falsy, the key is unchanged
 * up to the suffix sentinel "no-recv".
 */
export function keyWithReceiver(baseKey, receiverType) {
  return `${baseKey}::${hashReceiverType(receiverType)}`;
}
