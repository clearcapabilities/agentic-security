import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCorpus, summarizeCorpusStatus, TARGET_CWES, TARGET_LANGUAGES } from '../src/posture/corpus-status.js';

const entries = [
  { cve: 'A', cwe: 'CWE-89', language: 'javascript' },
  { cve: 'B', cwe: 'CWE-89', language: 'python' },
  { cve: 'C', cwe: 'CWE-79', language: 'javascript' },
];

test('analyzeCorpus tallies language/CWE and the coverage matrix', () => {
  const r = analyzeCorpus(entries, { target: 500 });
  assert.equal(r.total, 3);
  assert.equal(r.byLanguage.javascript, 2);
  assert.equal(r.byCwe['CWE-89'], 2);
  assert.equal(r.matrix['CWE-89'].python, 1);
  assert.equal(r.progressPct, 1);
  assert.equal(r.remainingToTarget, 497);
});

test('gaps are empty target cells and counts are consistent', () => {
  const r = analyzeCorpus(entries);
  assert.equal(r.cellsTotal, TARGET_CWES.length * TARGET_LANGUAGES.length);
  assert.equal(r.cellsCovered + r.gapCount, r.cellsTotal);
  // CWE-89/javascript is covered → not a gap; CWE-89/go is a gap.
  assert.ok(!r.gaps.some(g => g.cwe === 'CWE-89' && g.language === 'javascript'));
  assert.ok(r.gaps.some(g => g.cwe === 'CWE-89' && g.language === 'go'));
});

test('summarizeCorpusStatus renders progress + gaps', () => {
  const s = summarizeCorpusStatus(analyzeCorpus(entries));
  assert.match(s, /3\/500 entries/);
  assert.match(s, /cells covered/);
  assert.match(s, /example gaps:/);
});

test('handles empty / junk input without throwing', () => {
  const r = analyzeCorpus(null);
  assert.equal(r.total, 0);
  assert.equal(r.gapCount, r.cellsTotal);
});
