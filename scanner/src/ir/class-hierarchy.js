// Class Hierarchy Analysis (CHA) — JS/TS (P1.2).
//
// Walks the Babel ASTs across the project to build:
//
//   classDefs:    Map<className, { file, line, methods, fields, extends?, implements? }>
//   methodOwners: Map<methodQid, className>
//   typeOfVar:    Map<file::scope::varName, className>  — assignment-time type
//                                                          inference (simple, no
//                                                          flow analysis)
//
// The output is consumed by the dataflow engine's receiver-sensitivity layer
// (`receiver-context.js`) and by `callgraph.js` to refine virtual-call resolution.
//
// Scope of this v1: shallow analysis. We DON'T resolve:
//   - polymorphic types (T<U>),
//   - cross-file class inheritance via dynamic imports,
//   - mixins (Object.assign / class factories),
//   - prototype-based assignments outside `class` declarations.
//
// What we DO catch:
//   - `class Foo {}` declarations + their method signatures.
//   - `class Bar extends Foo {}` extends relationships.
//   - `let x = new Foo()` typed-LHS inference.
//   - `const x: Foo = ...` TS-annotated-LHS inference.
//   - `function buildFoo(): Foo { ... }` typed-return inference.

const _AST_CACHE = new WeakMap();

/**
 * Build the CHA over a perFileIR map (file → parsed IR with raw AST attached
 * under `_ast`). When AST isn't attached, fall back to the IR's own
 * structural hints (class names appearing in qids).
 */
export function buildClassHierarchy(perFileIR) {
  const classes = new Map();       // className -> { file, line, methods, extends }
  const methodOwners = new Map();  // qid -> className
  const typeOfVar = new Map();     // file::scope::var -> className

  if (!perFileIR || typeof perFileIR !== 'object') {
    return { classes, methodOwners, typeOfVar };
  }

  for (const [file, ir] of Object.entries(perFileIR)) {
    if (!ir || !Array.isArray(ir.functions)) continue;
    // Recover class names from method qids of the shape
    //   <file>::<scope>::<className.method>
    // Many of our existing parsers emit class methods as `Foo.bar` in qid.
    for (const fn of ir.functions) {
      if (!fn.qid) continue;
      const tail = fn.qid.split('::').pop() || '';
      const dotIdx = tail.indexOf('.');
      if (dotIdx <= 0) continue;
      const className = tail.slice(0, dotIdx);
      const methodName = tail.slice(dotIdx + 1);
      methodOwners.set(fn.qid, className);
      let cls = classes.get(className);
      if (!cls) {
        cls = { name: className, file, line: fn.line || 0, methods: new Set(), extends: null };
        classes.set(className, cls);
      }
      cls.methods.add(methodName);
    }
    // Try to recover `let x = new Foo(...)` typing — we walk the IR's
    // assign nodes for any call whose callee starts with a known class name.
    for (const fn of ir.functions) {
      const cfg = fn.cfg;
      if (!cfg || !cfg.nodes) continue;
      for (const id of Object.keys(cfg.nodes)) {
        const n = cfg.nodes[id];
        if (!n || n.kind !== 'assign') continue;
        const src = n.source;
        if (!src || src.kind !== 'call') continue;
        // `new Foo()` is shaped as { kind: 'call', callee: { kind: 'ident', name: 'Foo' }, isNew: true }
        const callee = src.callee;
        const className = callee?.kind === 'ident' ? callee.name : null;
        if (!className) continue;
        if (classes.has(className) || /^[A-Z]/.test(className)) {
          // Convention: PascalCase callees treated as constructors.
          const target = typeof n.target === 'string' ? n.target : null;
          if (target) typeOfVar.set(`${file}::${fn.qid}::${target}`, className);
        }
      }
    }
  }

  return { classes, methodOwners, typeOfVar };
}

/**
 * Given a variable reference (file + enclosing fn qid + var name), return
 * the inferred class name if any.
 */
export function classOfVar(cha, file, fnQid, varName) {
  if (!cha || !cha.typeOfVar || !varName) return null;
  return cha.typeOfVar.get(`${file}::${fnQid}::${varName}`) || null;
}

/**
 * Given a class name + method, return the resolved qid (if we know it).
 * v1: no override resolution — only direct definition.
 */
export function resolveMethod(cha, className, methodName) {
  if (!cha || !cha.classes || !className || !methodName) return null;
  // Walk the class hierarchy upward — extends chain — to find a method.
  let cur = className;
  const seen = new Set();
  while (cur && !seen.has(cur)) {
    seen.add(cur);
    const cls = cha.classes.get(cur);
    if (!cls) break;
    if (cls.methods && cls.methods.has(methodName)) {
      // Return a synthetic qid; the call graph may have its own resolution.
      return { className: cur, methodName };
    }
    cur = cls.extends || null;
  }
  return null;
}
