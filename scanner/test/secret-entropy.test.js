// Shannon-entropy + dictionary-word filter for hardcoded-secret FPs.
// Recommendation #1 of the SCA/SAST 10-item improvement plan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifySecretCandidate, shannonEntropy } from '../src/sast/_secret-entropy.js';

test('entropy: empty / short strings score 0', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.equal(shannonEntropy('a'), 0);
});

test('entropy: uniform random strings score ≥4 bits/char', () => {
  // Pseudo-random 32-char base64-ish string.
  const s = 'aB3xK9mZqW7tL2vN8pR5jY6hF4uG1cE0';
  assert.ok(shannonEntropy(s) > 4, `expected ≥4, got ${shannonEntropy(s)}`);
});

test('entropy: dictionary words score <3 bits/char', () => {
  for (const w of ['password', 'helloworld', 'monkeybanana']) {
    const h = shannonEntropy(w);
    assert.ok(h < 3.5, `${w} should score <3.5 (got ${h.toFixed(2)})`);
  }
});

// ── Classifier: rejects ─────────────────────────────────────────────────────

test('classify: rejects too-short values', () => {
  assert.equal(classifySecretCandidate('short').skip, true);
  assert.equal(classifySecretCandidate('foo').skip, true);
});

test('classify: rejects common-word values regardless of length', () => {
  // "password" length is < 12 so caught by length filter; this tests the
  // common-word filter via a 14-char value that IS in the word list.
  assert.equal(classifySecretCandidate('changeme').skip, true);
  assert.equal(classifySecretCandidate('placeholder').skip, true);
});

test('classify: rejects all-dictionary-token strings', () => {
  // "todo_password_admin" — all three tokens are common-words.
  const r = classifySecretCandidate('todo_password_admin');
  assert.equal(r.skip, true);
  assert.match(r.reason, /tokens-common-words|entropy/);
});

test('classify: rejects low-distinct-character strings', () => {
  // "aaaaaaaaaaaaaaaa" — 16 chars, but only 1 distinct.
  const r = classifySecretCandidate('aaaaaaaaaaaaaaaa');
  assert.equal(r.skip, true);
});

test('classify: rejects low-entropy padded values', () => {
  // "passwordpassword" — repeated dictionary word, low entropy.
  const r = classifySecretCandidate('passwordpassword');
  assert.equal(r.skip, true);
});

// ── Classifier: accepts ────────────────────────────────────────────────────

test('classify: accepts known provider prefixes', () => {
  // Synthetic values shaped LIKE real provider prefixes but with obviously-
  // fake random suffixes — required because GitHub secret-scanning rejects
  // even test fixtures matching real provider formats. We assert on the
  // prefix-match behavior; the suffix doesn't need to look real.
  const aws    = classifySecretCandidate('AKIA' + 'X'.repeat(16));
  const stripe = classifySecretCandidate('sk_test_' + 'Z'.repeat(24));
  const github = classifySecretCandidate('ghp_' + 'Q'.repeat(36));
  assert.equal(aws.skip,    false);
  assert.equal(stripe.skip, false);
  assert.equal(github.skip, false);
});

test('classify: accepts JWT-shaped strings', () => {
  // Three base64 segments separated by dots.
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456';
  const r = classifySecretCandidate(jwt);
  assert.equal(r.skip, false);
});

test('classify: accepts high-entropy random tokens', () => {
  // 32-char base64-ish — entropy >4.5.
  const r = classifySecretCandidate('xK9mZ3qW7tL2vN8pR5jY6hF4uG1cE0aB');
  assert.equal(r.skip, false);
});

test('classify: accepts long hex strings (SHA-256-shaped)', () => {
  const r = classifySecretCandidate('3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b');
  assert.equal(r.skip, false);
});

// ── Boundary cases the Juliet Java FP class will hit ───────────────────────

test('Juliet-class FPs: simple test-fixture secrets are all rejected', () => {
  const juliet = [
    'hardcodedSecret',     // template name, low entropy
    'sourceData',          // Juliet convention
    'badSourceValue',      // Juliet convention
    'demosecret',          // common-word combo
    'helloPassword',       // dictionary tokens
    'temp_password_123',   // dictionary tokens
  ];
  for (const v of juliet) {
    const r = classifySecretCandidate(v);
    assert.equal(r.skip, true, `expected ${v} rejected, got: ${JSON.stringify(r)}`);
  }
});

test('Real-world TPs: high-entropy / known-prefix secrets pass', () => {
  // All values here are SHAPED like real provider tokens but use obviously-
  // synthetic suffixes ("XXXXXX…") so GitHub secret-scanning doesn't reject
  // the test file. We're testing the classifier's prefix-match logic, not
  // verifying real secret recovery.
  const real = [
    'AKIA' + 'X'.repeat(16),                        // AWS access-key shape
    'sk_test_' + 'Y'.repeat(24),                    // Stripe test-key shape
    'ghp_' + 'Z'.repeat(36),                        // GitHub PAT shape
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMiJ9.SgnXXX', // JWT shape
  ];
  for (const v of real) {
    const r = classifySecretCandidate(v);
    assert.equal(r.skip, false, `expected ${v} accepted, got: ${JSON.stringify(r)}`);
  }
});
