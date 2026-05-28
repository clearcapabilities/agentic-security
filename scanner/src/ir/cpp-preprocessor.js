// Lightweight C/C++ preprocessor — Recommendation #8 of the SCA/SAST plan.
//
// Resolves `#include` + `#define BUF[N]` patterns across header files so
// the strcpy-destination-size guard (cpp.js#_classifyDestBuffer) can find
// buffer-size declarations declared in a sibling .h.
//
// Scope (v1, intentionally narrow):
//   - `#include "local.h"` resolved relative to the source file
//     (`#include <…>` system headers NOT resolved — they're too noisy
//     and don't carry security signal at this layer)
//   - `#define IDENT VALUE` — single-line object-like macros only;
//     function-like macros (`#define X(a,b) ...`) ignored in v1
//   - `typedef char BufT[N];` — alias expansion when N is literal
//
// What's intentionally OUT of scope:
//   - Multi-step macro expansion (cascade of #define A B / #define B C / use A)
//   - Conditional compilation (#ifdef / #if / #else): we union all branches
//   - Token-pasting (##) and stringification (#)
//   - Compiler -D flags (would require build-system integration)
//
// The goal is not to be a complete preprocessor; it's to recover the
// 80% of fixed-buffer-size context that Juliet C/C++ tests scatter across
// `header.h` (with `#define BUFSIZE 1024`) and `source.c` (with
// `char buf[BUFSIZE]; strcpy(buf, src);`).
//
// Output: { defines: Map<name, value>, typedefs: Map<name, {kind,size}>,
//           includes: string[] }
// where size is a literal integer when resolvable, null otherwise.

import * as fs from 'node:fs';
import * as path from 'node:path';

const _MAX_INCLUDE_DEPTH = 4;     // refuse pathological recursion
const _MAX_LINES_PER_FILE = 10_000; // skip auto-generated huge headers

function _parseDefines(content) {
  const defines = new Map();
  for (const m of content.matchAll(/^\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+?)(?:$|\/\*|\/\/)/gm)) {
    const name = m[1];
    let val = m[2].trim();
    // Strip trailing line continuation backslashes.
    val = val.replace(/\\\s*$/, '').trim();
    // Skip function-like macros for v1.
    if (val.startsWith('(') && /\b[A-Za-z_]\w*\s*\(/.test(val)) continue;
    defines.set(name, val);
  }
  return defines;
}

function _parseTypedefs(content) {
  const typedefs = new Map();
  // typedef char BufT[1024];  / typedef unsigned char Bytes[256];
  for (const m of content.matchAll(/typedef\s+(?:unsigned\s+|signed\s+)?(?:char|wchar_t|int8_t|uint8_t)\s+([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*|\d+)\s*\]\s*;/g)) {
    const name = m[1];
    const sizeTxt = m[2];
    let size = null;
    if (/^\d+$/.test(sizeTxt)) size = parseInt(sizeTxt, 10);
    typedefs.set(name, { kind: 'char-array', size, sizeExpr: sizeTxt });
  }
  return typedefs;
}

function _parseIncludes(content) {
  const includes = [];
  for (const m of content.matchAll(/^\s*#\s*include\s+"([^"]+)"/gm)) {
    includes.push(m[1]);
  }
  return includes;
}

function _resolveSize(sizeExpr, defines) {
  if (/^\d+$/.test(sizeExpr)) return parseInt(sizeExpr, 10);
  const macro = defines.get(sizeExpr);
  if (macro && /^\d+$/.test(macro)) return parseInt(macro, 10);
  return null;
}

/**
 * Recursively preprocess a single source file by walking its #includes.
 * Returns the merged define table + typedef table + flat list of resolved
 * include paths. Cycles are detected via the `visited` set.
 */
export function preprocessFile(sourcePath, opts = {}) {
  const visited = opts.visited || new Set();
  const depth = opts.depth || 0;
  const result = { defines: new Map(), typedefs: new Map(), includes: [] };

  const abs = path.resolve(sourcePath);
  if (visited.has(abs)) return result;
  visited.add(abs);
  if (depth > _MAX_INCLUDE_DEPTH) return result;

  let content;
  try { content = fs.readFileSync(abs, 'utf8'); }
  catch { return result; }
  if (content.split('\n').length > _MAX_LINES_PER_FILE) return result;

  // First pass on this file's own contents.
  const localDefines = _parseDefines(content);
  const localTypedefs = _parseTypedefs(content);
  const includes = _parseIncludes(content);

  // Recursive merge — header values are merged BEFORE local ones so that
  // a local #undef + redefine could in principle override (we don't model
  // #undef, but this ordering is the correct future-extension point).
  const dir = path.dirname(abs);
  for (const inc of includes) {
    const child = preprocessFile(path.join(dir, inc), { visited, depth: depth + 1 });
    for (const [k, v] of child.defines) if (!result.defines.has(k)) result.defines.set(k, v);
    for (const [k, v] of child.typedefs) if (!result.typedefs.has(k)) result.typedefs.set(k, v);
    result.includes.push(...child.includes, inc);
  }
  for (const [k, v] of localDefines) result.defines.set(k, v);
  for (const [k, v] of localTypedefs) result.typedefs.set(k, v);

  // Final pass — resolve typedef sizes that referenced a macro.
  for (const [name, td] of result.typedefs) {
    if (td.size === null && td.sizeExpr) {
      const resolved = _resolveSize(td.sizeExpr, result.defines);
      if (resolved !== null) result.typedefs.set(name, { ...td, size: resolved });
    }
  }
  return result;
}

/**
 * Resolve a buffer-size expression in the context of a preprocessed file.
 * Accepts either a literal integer string or a macro name. Returns the
 * integer size, or null if unresolvable.
 */
export function resolveSize(sizeExpr, preprocessed) {
  return _resolveSize(sizeExpr, preprocessed.defines || new Map());
}

/**
 * Resolve a typedef name to its size, if it's a char-array typedef.
 */
export function resolveTypedef(name, preprocessed) {
  return preprocessed.typedefs.get(name) || null;
}

export const _internals = { _parseDefines, _parseTypedefs, _parseIncludes };
