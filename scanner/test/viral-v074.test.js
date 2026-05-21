// v0.74 viral-surface tests: poc-video + personality + compare.
// (security-tutor skill tested via skills-registry tests.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePocScript, _internal as pocInt } from '../src/poc-video.js';
import { getPersonality, applyPersonality, listPersonalities, _internal as persInt } from '../src/personality.js';
import { compareFindings, renderComparison, _internal as cmpInt } from '../src/compare.js';

// ─── PoC video ─────────────────────────────────────────────────────────────

test('generatePocScript: SQLi finding gets a curl script with the exploit input', () => {
  const f = {
    cwe: 'CWE-89', vuln: 'SQL Injection (cursor.execute)',
    file: 'app.py', line: 14,
    _exploitInput: "1' OR '1'='1",
  };
  const r = generatePocScript(f, { baseUrl: 'https://staging.example.com', route: '/api/users' });
  assert.equal(r.format, 'curl');
  assert.match(r.script, /#!/);
  assert.match(r.script, /OR/);
  assert.match(r.script, /staging.example.com/);
  assert.match(r.filename, /\.sh$/);
});

test('generatePocScript: XSS finding defaults to playwright format', () => {
  const f = {
    cwe: 'CWE-79', vuln: 'DOM XSS', file: 'app.js', line: 22,
    _exploitInput: '<script>alert(1)</script>',
  };
  const r = generatePocScript(f);
  assert.equal(r.format, 'playwright');
  assert.match(r.script, /playwright/);
  assert.match(r.script, /screenshot/);
  assert.match(r.filename, /\.spec\.ts$/);
});

test('generatePocScript: explicit format override beats default', () => {
  const f = { cwe: 'CWE-79', vuln: 'XSS', file: 'a', line: 1, _exploitInput: 'x' };
  const r = generatePocScript(f, { format: 'http' });
  assert.equal(r.format, 'http');
  assert.match(r.script, /HTTP\/1\.1/);
});

test('generatePocScript: unknown CWE falls back to a generic payload', () => {
  const f = { cwe: 'CWE-99999', vuln: 'unknown', file: 'a', line: 1 };
  const r = generatePocScript(f);
  assert.ok(r.script.length > 0);
  // Default format derivation works; payload may be the fallback.
  assert.ok(['curl', 'playwright', 'http'].includes(r.format));
});

test('poc-video: _defaultFormatFor maps UI vs backend CWEs correctly', () => {
  assert.equal(pocInt._defaultFormatFor('CWE-79'), 'playwright');
  assert.equal(pocInt._defaultFormatFor('CWE-601'), 'playwright');
  assert.equal(pocInt._defaultFormatFor('CWE-89'), 'curl');
  assert.equal(pocInt._defaultFormatFor('CWE-78'), 'curl');
});

// ─── Personality ───────────────────────────────────────────────────────────

test('getPersonality: returns the named voice; falls back to sage', () => {
  assert.equal(getPersonality('sage').glyph, '🛡');
  assert.equal(getPersonality('cassandra').glyph, '🚨');
  assert.equal(getPersonality('vince').glyph, '🪖');
  assert.equal(getPersonality('nonexistent').glyph, '🛡');     // → sage default
});

test('listPersonalities returns the three voices', () => {
  const voices = listPersonalities();
  assert.ok(voices.includes('sage'));
  assert.ok(voices.includes('cassandra'));
  assert.ok(voices.includes('vince'));
});

test('applyPersonality: cassandra rewrites the opening to be alarmist', () => {
  const baseRendered = `### 🛡 agentic-security

I looked at the 2 files you changed and noticed 3 new findings worth your attention.

🟥 **SQL injection** — \`/api/users\` (\`app.js:14\`)
  > example body

---
**Blocking merge:** 1 critical + 2 high.`;
  const delta = {
    changedFiles: ['a.js', 'b.js'],
    introduced: [{ severity: 'critical' }, { severity: 'high' }, { severity: 'high' }],
    resolved: [], shifted: [],
    summary: { introduced: { critical: 1, high: 2 }, resolved: {} },
  };
  const cassandra = applyPersonality(baseRendered, delta, 'cassandra');
  assert.match(cassandra, /🚨/);
  assert.match(cassandra, /attack surface/);
  assert.match(cassandra, /DO NOT MERGE/);
});

test('applyPersonality: vince has drill-sergeant closing', () => {
  const baseRendered = `### 🛡 agentic-security

I looked at the 1 file you changed and noticed 1 new finding worth your attention.

🟥 finding

---
**Blocking merge:** 1 critical.`;
  const delta = {
    changedFiles: ['a.js'],
    introduced: [{ severity: 'critical' }],
    resolved: [], shifted: [],
    summary: { introduced: { critical: 1, high: 0 }, resolved: {} },
  };
  const vince = applyPersonality(baseRendered, delta, 'vince');
  assert.match(vince, /🪖/);
  assert.match(vince, /HALT/);
  assert.match(vince, /3am/);
});

test('applyPersonality: sage preserves the calm tone', () => {
  const baseRendered = `### 🛡 agentic-security

Existing line.

---
**Blocking merge:**`;
  const delta = {
    changedFiles: [], introduced: [], resolved: [], shifted: [],
    summary: { introduced: {}, resolved: {} },
    head: { summary: { total: 0 } },
  };
  const sage = applyPersonality(baseRendered, delta, 'sage');
  // Sage opening for zero-delta is the "Safe to merge." form.
  assert.match(sage, /merge/i);
});

// ─── Compare runner ────────────────────────────────────────────────────────

test('_normalizeSeverity maps common other-tool conventions', () => {
  assert.equal(cmpInt._normalizeSeverity('Critical'), 'critical');
  assert.equal(cmpInt._normalizeSeverity('ERROR'), 'critical');
  assert.equal(cmpInt._normalizeSeverity('warning'), 'high');
  assert.equal(cmpInt._normalizeSeverity('5'), 'critical');
  assert.equal(cmpInt._normalizeSeverity(null), 'info');
  assert.equal(cmpInt._normalizeSeverity('bogus'), 'info');
});

test('compareFindings: detects overlap when both flag same file:line', () => {
  const ours = [
    { file: 'app.js', line: 14, severity: 'high', vuln: 'SQLi', cwe: 'CWE-89' },
    { file: 'app.js', line: 22, severity: 'medium', vuln: 'XSS', cwe: 'CWE-79' },
  ];
  const theirs = [
    { file: 'app.js', line: 14, severity: 'critical', vuln: 'sql injection', cwe: 'CWE-89' },
    { file: 'app.js', line: 99, severity: 'low', vuln: 'unused var', cwe: null },
  ];
  const c = compareFindings(ours, theirs);
  assert.equal(c.overlap.length, 1);
  assert.equal(c.oursOnly.length, 1);
  assert.equal(c.theirsOnly.length, 1);
  // Severity disagreement: high vs critical.
  assert.equal(c.severityShift.length, 1);
});

test('compareFindings: ±2 line tolerance for overlap', () => {
  const ours   = [{ file: 'a.js', line: 14, severity: 'high', vuln: 'v' }];
  const theirs = [{ file: 'a.js', line: 16, severity: 'high', vuln: 'v' }];
  const c = compareFindings(ours, theirs);
  assert.equal(c.overlap.length, 1, 'lines 14 and 16 should match within ±2');
});

test('renderComparison: produces a Markdown card with the right sections', () => {
  const ours = [{ file: 'a.js', line: 1, severity: 'high', vuln: 'a-only', cwe: 'CWE-89' }];
  const theirs = [{ file: 'b.js', line: 1, severity: 'medium', vuln: 'b-only', cwe: null }];
  const md = renderComparison(compareFindings(ours, theirs), {
    ourName: 'agentic-security', otherName: 'other-tool',
  });
  assert.match(md, /^# Comparison/m);
  assert.match(md, /agentic-security/);
  assert.match(md, /other-tool/);
  assert.match(md, /only agentic-security caught/);
  assert.match(md, /only other-tool caught/);
});

test('renderComparison: perfect overlap message when both tools agree', () => {
  const f = [{ file: 'a.js', line: 1, severity: 'high', vuln: 'v' }];
  const md = renderComparison(compareFindings(f, f));
  assert.match(md, /Perfect overlap/);
});
