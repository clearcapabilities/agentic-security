// R13 — "provably safe" first-class verdict tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateProofGate, verdictForFinding } from '../src/dataflow/proof-gate.js';

test('proven-clean finding is marked provablySafe', () => {
  const f = { parser: 'IR-TAINT', vuln: 'SQL Injection', severity: 'high', confidence: 0.8, provenClean: true };
  annotateProofGate([f]);
  assert.equal(f.proof.verdict, 'proven-clean');
  assert.equal(f.provablySafe, true);
  assert.ok(f.confidence < 0.8, 'confidence is still demoted');
});

test('proven-infeasible finding is marked provablySafe', () => {
  const f = { parser: 'IR-TAINT', vuln: 'XSS', severity: 'high', confidence: 0.7, _provenUnreachable: true };
  annotateProofGate([f]);
  assert.equal(f.proof.verdict, 'proven-infeasible');
  assert.equal(f.provablySafe, true);
});

test('feasible / unproven findings are NOT provablySafe', () => {
  const feasible = { parser: 'IR-TAINT', vuln: 'SQL Injection', severity: 'high', confidence: 0.8 };
  const unproven = { parser: 'REGEX', vuln: 'Weak Hash', severity: 'medium', confidence: 0.6 };
  annotateProofGate([feasible, unproven]);
  assert.ok(!feasible.provablySafe);
  assert.ok(!unproven.provablySafe);
  assert.equal(feasible.confidence, 0.8, 'feasible confidence untouched');
});

test('verdictForFinding maps the upstream proof signals', () => {
  assert.equal(verdictForFinding({ provenClean: true }).verdict, 'proven-clean');
  assert.equal(verdictForFinding({ _provenUnreachable: true }).verdict, 'proven-infeasible');
  assert.equal(verdictForFinding({ parser: 'IR-TAINT' }).verdict, 'feasible');
});
