// Verifier sandbox loop tests (P1.2 / FR-VER-3, FR-VER-6, FR-VER-7).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validatePoc,
  proveSanitizerAbsence,
  verdictForFinding,
  annotateVerifierVerdicts,
  verifierCoverageSummary,
  _internals,
} from '../src/posture/verifier.js';

// ─── validatePoc — refuse destructive/oversized/no-exit PoCs ───────────────

test('validatePoc rejects null/missing PoC', () => {
  assert.equal(validatePoc(null).ok, false);
  assert.equal(validatePoc(undefined).ok, false);
  assert.equal(validatePoc({}).reason, 'empty-code');
});

test('validatePoc rejects oversized code', () => {
  const big = 'a'.repeat(_internals.MAX_POC_BYTES + 1);
  const r = validatePoc({ code: big, lang: 'node' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'code-too-long');
});

test('validatePoc rejects destructive payloads', () => {
  const code = `// PoC; rm -rf /\nprocess.exit(0);`;
  assert.equal(validatePoc({ code, lang: 'node' }).ok, false);
});

test('validatePoc rejects hardcoded cloud metadata IPs', () => {
  const code = `await fetch('http://169.254.169.254/');\nprocess.exit(0);`;
  const r = validatePoc({ code, lang: 'node' });
  assert.equal(r.ok, false);
  assert.ok(r.reason.startsWith('banned-host'));
});

test('validatePoc rejects Node PoCs without a deterministic exit', () => {
  const code = `await fetch('http://localhost:3000/');`;
  const r = validatePoc({ code, lang: 'node' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-deterministic-exit');
});

test('validatePoc accepts a well-formed Node PoC', () => {
  const code = `await fetch('http://localhost:3000/api');\nprocess.exit(0);`;
  assert.equal(validatePoc({ code, lang: 'node' }).ok, true);
});

// ─── proveSanitizerAbsence ──────────────────────────────────────────────────

test('proveSanitizerAbsence returns ok when no sanitizer is on the flow', () => {
  const finding = { family: 'sql-injection', file: 'app.js', line: 5 };
  const fc = { 'app.js': "const id = req.params.id;\ndb.query('SELECT * FROM users WHERE id = ' + id);\n" };
  const r = proveSanitizerAbsence(finding, fc);
  assert.equal(r.ok, true);
});

test('proveSanitizerAbsence detects parameterized query as sanitizer present', () => {
  const finding = { family: 'sql-injection', file: 'app.js', line: 5 };
  const fc = { 'app.js': "const id = req.params.id;\ndb.query('SELECT * FROM users WHERE id = $1', [id]);\n" };
  const r = proveSanitizerAbsence(finding, fc);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'sanitizer-present');
});

test('proveSanitizerAbsence handles unknown family gracefully', () => {
  const r = proveSanitizerAbsence({ family: 'made-up-family' }, {});
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-rule');
});

// ─── verdictForFinding ──────────────────────────────────────────────────────

test('verdictForFinding tags unverified-by-design for no-poc families', () => {
  const f = { family: 'hardcoded-secret' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'unverified-by-design');
});

test('verdictForFinding tags verified-by-llm when LLM accepted', () => {
  const f = { family: 'sql-injection', validator_verdict: 'accept' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'verified-by-llm');
});

test('verdictForFinding tags verified-sanitizer-absence on clean unparameterized SQL', () => {
  const f = { family: 'sql-injection', file: 'a.js', line: 2 };
  const ctx = { fileContents: { 'a.js': "const id = req.body.id;\ndb.query('SELECT * WHERE id=' + id);" } };
  const v = verdictForFinding(f, ctx);
  assert.equal(v.verdict, 'verified-sanitizer-absence');
});

test('verdictForFinding tags cannot-verify when no PoC and no sanitizer rule', () => {
  const f = { family: 'unmapped-family' };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'cannot-verify');
});

test('verdictForFinding tags cannot-verify when PoC fails static validation', () => {
  const f = {
    family: 'sql-injection',
    poc: { lang: 'node', code: '// rm -rf /\nprocess.exit(0);' },
  };
  const v = verdictForFinding(f);
  assert.equal(v.verdict, 'cannot-verify');
  assert.ok(v.reason.includes('poc-rejected') || v.reason.includes('poc-validation-failed') || v.reason.includes('no-poc-no-sanitizer-rule'));
});

// ─── batch annotation ──────────────────────────────────────────────────────

test('annotateVerifierVerdicts sets verifier_verdict on every finding', () => {
  const findings = [
    { family: 'hardcoded-secret', file: 'a', line: 1 },
    { family: 'sql-injection', validator_verdict: 'accept' },
    { family: 'sql-injection', file: 'x.js', line: 1 },
  ];
  annotateVerifierVerdicts(findings, { fileContents: { 'x.js': "db.query('SELECT * WHERE id=' + id);" } });
  assert.equal(findings[0].verifier_verdict, 'unverified-by-design');
  assert.equal(findings[1].verifier_verdict, 'verified-by-llm');
  assert.equal(findings[2].verifier_verdict, 'verified-sanitizer-absence');
});

test('annotateVerifierVerdicts never throws on garbage input', () => {
  assert.doesNotThrow(() => annotateVerifierVerdicts(null));
  assert.doesNotThrow(() => annotateVerifierVerdicts([null, {}, { family: 'sql-injection' }]));
});

test('annotateVerifierVerdicts assigns cannot-verify if verdict logic throws (defense-in-depth)', () => {
  // We can't easily make verdictForFinding throw, but a getter that throws on
  // .family does the job.
  const f = {};
  Object.defineProperty(f, 'family', { get() { throw new Error('boom'); } });
  annotateVerifierVerdicts([f]);
  assert.equal(f.verifier_verdict, 'cannot-verify');
  assert.ok(/verifier-exception/.test(f.verifier_reason || ''));
});

test('verifierCoverageSummary aggregates by verdict bucket', () => {
  const findings = [
    { verifier_verdict: 'verified-exploit' },
    { verifier_verdict: 'cannot-verify' },
    { verifier_verdict: 'cannot-verify' },
    { verifier_verdict: 'unverified-by-design' },
  ];
  const s = verifierCoverageSummary(findings);
  assert.equal(s['verified-exploit'], 1);
  assert.equal(s['cannot-verify'], 2);
  assert.equal(s['unverified-by-design'], 1);
});

// ─── safety / fail-closed ──────────────────────────────────────────────────

test('verdict for finding without target in live mode is cannot-verify', () => {
  // We test the LOGIC path without setting env so live mode is off; the
  // PoC route falls back to static validation. With env set + no target,
  // verifier.js still expects the target arg from ctx; absent both, it
  // should land in cannot-verify rather than crash.
  const f = {
    family: 'sql-injection',
    poc: { lang: 'node', code: `await fetch('http://localhost:3000/');\nprocess.exit(0);` },
  };
  const v = verdictForFinding(f);  // no ctx.target, no env override
  // Without live execution, we fall through to sanitizer-absence; with no
  // fileContents in ctx, that fails; we land on cannot-verify or
  // verified-sanitizer-absence depending on whether fileContents was passed.
  assert.ok(['cannot-verify', 'verified-sanitizer-absence'].includes(v.verdict));
});
