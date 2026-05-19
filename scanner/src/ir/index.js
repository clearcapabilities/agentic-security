// IR entry point.
//
// Build per-file IR for every JS/TS/Python/Java file in a project, then
// build the cross-file call graph on top.

import { parseJsFile } from './parser-js.js';
import { parsePythonFile } from './parser-py.js';
import { parseJavaFile } from './parser-java.js';
import { buildCallGraph } from './callgraph.js';
import { buildClassHierarchy } from './class-hierarchy.js';
import { computeSSA, isSSAEnabled } from './ssa.js';

// Synchronous default — JS/TS + Python only. Engine.js calls this directly.
// Java IR requires async import of java-parser; callers who want it can use
// buildProjectIRAsync instead.
export function buildProjectIR(fileContents) {
  const perFile = {};
  for (const [file, code] of Object.entries(fileContents || {})) {
    let ir = null;
    if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) ir = parseJsFile(file, code);
    else if (/\.py$/i.test(file)) ir = parsePythonFile(file, code);
    if (ir) perFile[file] = ir;
  }
  if (isSSAEnabled()) {
    for (const ir of Object.values(perFile)) {
      for (const fn of (ir.functions || [])) {
        try { computeSSA(fn.cfg); } catch {}
      }
    }
  }
  const cg = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile);
  return { perFile, callGraph: cg, cha };
}

// Async variant — includes Java IR via java-parser.
export async function buildProjectIRAsync(fileContents) {
  const perFile = {};
  for (const [file, code] of Object.entries(fileContents || {})) {
    let ir = null;
    if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) ir = parseJsFile(file, code);
    else if (/\.py$/i.test(file)) ir = parsePythonFile(file, code);
    else if (/\.java$/i.test(file)) {
      try { ir = await parseJavaFile(file, code); } catch { ir = null; }
    }
    if (ir) perFile[file] = ir;
  }
  if (isSSAEnabled()) {
    for (const ir of Object.values(perFile)) {
      for (const fn of (ir.functions || [])) {
        try { computeSSA(fn.cfg); } catch {}
      }
    }
  }
  const cg = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile);
  return { perFile, callGraph: cg, cha };
}

export { parseJsFile, parsePythonFile, parseJavaFile, buildCallGraph, buildClassHierarchy, computeSSA, isSSAEnabled };
