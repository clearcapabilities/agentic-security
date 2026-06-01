// R17 — finding-provenance / corroboration tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateFindingProvenance as annotateProvenance } from '../src/posture/provenance.js';

test('single-signal finding: corroborationCount 1, no multiSignal', () => {
  const [f] = annotateProvenance([{ parser: 'AST', vuln: 'X' }]);
  assert.equal(f.corroborationCount, 1);
  assert.deepEqual(f.corroboration.by, ['AST']);
  assert.ok(!f.multiSignal);
});

test('merged finding: union of parser + evidence, deduped, multiSignal', () => {
  // dedup sets evidence to [winnerParser, ...loserParsers]; parser may repeat.
  const [f] = annotateProvenance([{ parser: 'IR-TAINT', evidence: ['IR-TAINT', 'REGEX', 'STRUCTURAL'] }]);
  assert.equal(f.corroborationCount, 3);
  assert.deepEqual(f.corroboration.by, ['IR-TAINT', 'REGEX', 'STRUCTURAL']);
  assert.equal(f.multiSignal, true);
});

test('LLM-validator accept and dynamic confirmation count as independent signals', () => {
  const [a] = annotateProvenance([{ parser: 'AST', validator_verdict: 'accept' }]);
  assert.ok(a.corroboration.by.includes('llm-validator') && a.corroborationCount === 2);
  const [b] = annotateProvenance([{ parser: 'AST', dynamicallyConfirmed: true }]);
  assert.ok(b.corroboration.by.includes('dynamic') && b.corroborationCount === 2);
  // 'unvalidated' / 'reject' do NOT add a positive signal.
  const [c] = annotateProvenance([{ parser: 'AST', validator_verdict: 'unvalidated' }]);
  assert.equal(c.corroborationCount, 1);
});

test('no parser → UNKNOWN, count 1; non-objects tolerated', () => {
  const out = annotateProvenance([{ vuln: 'Y' }, null]);
  assert.equal(out[0].corroborationCount, 1);
  assert.deepEqual(out[0].corroboration.by, ['UNKNOWN']);
});

test('ranking tiebreaker: multiSignal sorts above single-signal at equal severity', () => {
  // Mirror the engine's final-sort comparator tail.
  const findings = annotateProvenance([
    { parser: 'REGEX', severity: 'high' },
    { parser: 'IR-TAINT', evidence: ['IR-TAINT', 'REGEX'], severity: 'high' },
  ]);
  findings.sort((a, b) =>
    ({ critical: 0, high: 1, medium: 2, low: 3 }[a.severity] ?? 4) - ({ critical: 0, high: 1, medium: 2, low: 3 }[b.severity] ?? 4)
    || ((b.corroborationCount || 1) - (a.corroborationCount || 1)));
  assert.equal(findings[0].corroborationCount, 2, 'the corroborated finding should rank first');
});
