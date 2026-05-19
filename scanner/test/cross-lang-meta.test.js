// FR-CHAIN-FILTER + FR-FAMILY-REGISTRY tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isChainWorthy,
  chainWorthyFindings,
  familyForBoundary,
  XLANG_FAMILIES,
  _internals,
} from '../src/posture/cross-lang-meta.js';

// ─── FR-CHAIN-FILTER ──────────────────────────────────────────────────────

test('isChainWorthy is true for injection-class families', () => {
  for (const fam of ['sql-injection', 'command-injection', 'xss', 'ssrf', 'code-injection', 'xxe', 'insecure-deserialization']) {
    assert.equal(isChainWorthy({ family: fam }), true, `${fam} should be chain-worthy`);
  }
});

test('isChainWorthy is false for incidental families', () => {
  for (const fam of ['csrf', 'header-hardening', 'data-exposure', 'hardcoded-secret', 'weak-rng', 'audit-logging']) {
    assert.equal(isChainWorthy({ family: fam }), false, `${fam} should NOT be chain-worthy`);
  }
});

test('isChainWorthy handles null/undefined/no-family', () => {
  assert.equal(isChainWorthy(null), false);
  assert.equal(isChainWorthy(undefined), false);
  assert.equal(isChainWorthy({}), false);
  assert.equal(isChainWorthy({ family: null }), false);
});

test('chainWorthyFindings filters arrays', () => {
  const findings = [
    { family: 'sql-injection' },
    { family: 'csrf' },
    { family: 'xss' },
    { family: null },
    null,
  ];
  const r = chainWorthyFindings(findings);
  assert.equal(r.length, 2);
  assert.deepEqual(r.map(f => f.family), ['sql-injection', 'xss']);
});

test('CHAIN_WORTHY_FAMILIES is a Set of strings', () => {
  assert.ok(_internals.CHAIN_WORTHY_FAMILIES instanceof Set);
  assert.ok(_internals.CHAIN_WORTHY_FAMILIES.size >= 10);
});

// ─── FR-FAMILY-REGISTRY ─────────────────────────────────────────────────────

test('familyForBoundary returns canonical names', () => {
  assert.equal(familyForBoundary('openapi'), 'xlang-openapi');
  assert.equal(familyForBoundary('grpc'),    'xlang-grpc');
  assert.equal(familyForBoundary('graphql'), 'xlang-graphql');
  assert.equal(familyForBoundary('queue'),   'xlang-queue');
  assert.equal(familyForBoundary('orm'),     'xlang-orm');
  assert.equal(familyForBoundary('iac'),     'xlang-iac');
});

test('familyForBoundary defaults to xlang-unknown for novel boundaries', () => {
  assert.equal(familyForBoundary('mqtt'), 'xlang-unknown');
  assert.equal(familyForBoundary(''), 'xlang-unknown');
  assert.equal(familyForBoundary(null), 'xlang-unknown');
  assert.equal(familyForBoundary(undefined), 'xlang-unknown');
});

test('XLANG_FAMILIES is frozen and stable', () => {
  assert.ok(Object.isFrozen(XLANG_FAMILIES));
  assert.equal(Object.keys(XLANG_FAMILIES).length, 6);
});
