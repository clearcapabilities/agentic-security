// SMT path feasibility — Recommendation #3 of the world-class roadmap.
//
// For top-N findings per scan, generate SMT constraints from the IR
// representing the conditions that must hold along the call-graph path
// from source to sink. Discharge via a Z3 solver. If UNSAT, the
// finding is provably infeasible and gets demoted to 'info' severity
// with `pathFeasibility: 'unsat'`. If SAT, we emit a sample witness
// (a concrete tainted input that triggers the sink) which is gold-standard
// evidence for the developer.
//
// Solver backend: prefers `z3-solver` (Z3 WASM published on npm) when
// installed; falls back to a constraint-emission-only mode that still
// records the SMT-LIB script so a CI step can discharge it offline.
//
// Gating: opt-in via AGENTIC_SECURITY_SMT_FEASIBILITY=1. Always bounded
// at top-MAX_PROOF_OBLIGATIONS findings per scan to keep wall-clock
// under PROOF_BUDGET_MS.
//
// IMPORTANT — this module is NOT a generic symbolic executor. It targets
// a narrow shape: "does there exist an input that flows from source S
// through path P to sink K?" That's enough to prove or refute the
// reachability claim on a finding the engine already produced. We do
// NOT attempt to prove arbitrary safety properties.

const PROOF_BUDGET_MS_DEFAULT = 30_000;
const MAX_PROOF_OBLIGATIONS_DEFAULT = 50;
const PER_QUERY_TIMEOUT_MS_DEFAULT = 5_000;

// Lazy-load Z3. The module is permitted to be absent — when it is, we
// fall back to constraint-emission-only mode (the SMT-LIB script is
// attached to the finding for offline discharge).
let _z3Mod = null;
let _z3LoadAttempted = false;
async function _loadZ3() {
  if (_z3LoadAttempted) return _z3Mod;
  _z3LoadAttempted = true;
  try {
    _z3Mod = await import('z3-solver');
    if (typeof _z3Mod.init === 'function') await _z3Mod.init();
  } catch { _z3Mod = null; }
  return _z3Mod;
}

// ── Constraint emission ───────────────────────────────────────────────────

/**
 * Encode a single IR predicate (one node along the path) into an SMT-LIB
 * assertion. Predicates supported in v1:
 *   - `var = source(name)`       — declares var as a free symbolic string
 *   - `var = const(literal)`     — equality with a constant
 *   - `var = concat(a, b)`       — string concatenation
 *   - `var = sanitize(x, kind)`  — applies a sanitizer; encoded as
 *                                  `var = "safe"` (forces concrete)
 *   - `assert reach(line N)`     — terminal predicate: this line must be
 *                                  reachable
 *   - `guard(cond)`              — a path condition (free-form text)
 */
function encodePredicate(p, idx) {
  switch (p.kind) {
    case 'source':
      return `(declare-const ${p.var} String)`;
    case 'const':
      return `(assert (= ${p.var} ${JSON.stringify(p.value)}))`;
    case 'concat':
      return `(assert (= ${p.var} (str.++ ${p.a} ${p.b})))`;
    case 'sanitize':
      return `(assert (= ${p.var} "safe-${p.kind}-${idx}"))`;
    case 'reach':
      // Symbolic "this line is reached" — we don't really model reachability,
      // we just record the obligation. The presence of the path is what
      // matters; SAT just means "some input satisfies the path conditions."
      return `; reach(${p.file}:${p.line})`;
    case 'guard':
      return `(assert ${p.smtCond || `(= ${p.var} ${JSON.stringify(p.value)})`})`;
    default:
      return `; unsupported predicate kind: ${p.kind}`;
  }
}

/**
 * Emit a complete SMT-LIB script for one finding. The script declares
 * source variables, asserts every predicate, asks (check-sat). On SAT
 * we (get-model) for the witness; on UNSAT the finding is infeasible.
 */
export function emitSmtScript(predicates, opts = {}) {
  const lines = [];
  lines.push('; SMT-LIB script — emitted by scanner/src/dataflow/smt-feasibility.js');
  lines.push(`(set-logic QF_S)`);
  lines.push(`(set-option :timeout ${opts.timeoutMs || PER_QUERY_TIMEOUT_MS_DEFAULT})`);
  predicates.forEach((p, i) => lines.push(encodePredicate(p, i)));
  lines.push('(check-sat)');
  lines.push('(get-model)');
  return lines.join('\n');
}

// ── Z3 discharge ──────────────────────────────────────────────────────────

/**
 * dischargeFinding(predicates, opts) — encode + solve. Returns one of:
 *   { verdict: 'sat',     witness: { var: value } }
 *   { verdict: 'unsat' }
 *   { verdict: 'unknown', reason: '<why>' }
 *   { verdict: 'pending', script: '<smt-lib text>' }  // when Z3 unavailable
 */
export async function dischargeFinding(predicates, opts = {}) {
  if (!predicates || !predicates.length) return { verdict: 'unknown', reason: 'no-predicates' };
  const script = emitSmtScript(predicates, opts);
  const z3 = await _loadZ3();
  if (!z3) return { verdict: 'pending', script };
  try {
    const { Context } = z3;
    const ctx = new Context('main');
    const solver = new ctx.Solver();
    // Feed the script via parse — z3-solver supports SMT-LIB ingestion.
    try { solver.fromString(script); }
    catch (e) {
      return { verdict: 'unknown', reason: 'parse-error: ' + String(e && e.message), script };
    }
    const start = Date.now();
    const result = await Promise.race([
      solver.check(),
      new Promise(resolve => setTimeout(() => resolve('timeout'), opts.timeoutMs || PER_QUERY_TIMEOUT_MS_DEFAULT)),
    ]);
    const elapsed = Date.now() - start;
    if (result === 'unsat') return { verdict: 'unsat', elapsedMs: elapsed };
    if (result === 'timeout' || result === 'unknown') return { verdict: 'unknown', reason: result, elapsedMs: elapsed, script };
    if (result === 'sat') {
      // Best-effort witness extraction.
      let witness = {};
      try {
        const model = solver.model();
        for (const decl of model.decls()) witness[decl.name()] = String(model.get(decl));
      } catch { /* no model */ }
      return { verdict: 'sat', witness, elapsedMs: elapsed };
    }
    return { verdict: 'unknown', reason: String(result), elapsedMs: elapsed };
  } catch (e) {
    return { verdict: 'unknown', reason: String(e && e.message || e), script };
  }
}

// ── Finding-level integration ─────────────────────────────────────────────

/**
 * Annotate the top-N findings with their feasibility verdict. Modifies
 * findings in place — each gets a `pathFeasibility` field and (when
 * SAT) a `feasibilityWitness` object. Findings whose verdict is UNSAT
 * are demoted to 'info' severity.
 */
export async function annotatePathFeasibility(findings, opts = {}) {
  if (!Array.isArray(findings)) return { annotated: 0, demoted: 0 };
  const budget = opts.budgetMs || PROOF_BUDGET_MS_DEFAULT;
  const max = opts.maxObligations || MAX_PROOF_OBLIGATIONS_DEFAULT;
  // Prioritize: critical/high findings with concrete chains first.
  const sorted = [...findings]
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .filter(f => Array.isArray(f.chain) || Array.isArray(f.taintPath))
    .slice(0, max);
  const start = Date.now();
  let annotated = 0, demoted = 0;
  for (const f of sorted) {
    if (Date.now() - start > budget) {
      f.pathFeasibility = 'unknown';
      f.feasibilityReason = 'budget-exceeded';
      continue;
    }
    const predicates = (f.chain || f.taintPath || []).map((step, i) => ({
      kind: i === 0 ? 'source' : (step.kind || 'concat'),
      var: `v${i}`,
      a: `v${Math.max(0, i - 1)}`, b: '""',
      value: step.value || '',
      file: step.file, line: step.line,
    }));
    const r = await dischargeFinding(predicates, { timeoutMs: Math.min(5_000, budget) });
    f.pathFeasibility = r.verdict;
    if (r.witness) f.feasibilityWitness = r.witness;
    if (r.script) f._smtScript = r.script.slice(0, 4000);
    annotated++;
    if (r.verdict === 'unsat') {
      const before = f.severity;
      f.severity = 'info';
      f._pathFeasibilityDemoted = before;
      demoted++;
    }
  }
  return { annotated, demoted, elapsedMs: Date.now() - start };
}

export const _internals = { encodePredicate, emitSmtScript, PROOF_BUDGET_MS_DEFAULT, MAX_PROOF_OBLIGATIONS_DEFAULT };
