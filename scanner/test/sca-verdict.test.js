// R12 — deterministic SCA verdict tests. One case per rule in the ordered
// procedure, plus version helpers and the annotator.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeScaVerdict, annotateScaVerdicts, parseVersion, bumpKind, SCA_VERDICTS } from '../src/posture/sca-verdict.js';

const base = (over = {}) => ({
  type: 'vulnerable_dep', name: 'lodash', ecosystem: 'npm', version: '4.17.20',
  fixedVersions: ['4.17.21'], reachabilityTier: 'function-reachable', compositeRiskTier: 'high', ...over,
});

test('parseVersion + bumpKind', () => {
  assert.deepEqual(parseVersion('v4.17.20'), { major: 4, minor: 17, patch: 20 });
  assert.deepEqual(parseVersion('5'), { major: 5, minor: 0, patch: 0 });
  assert.equal(parseVersion('not-a-version'), null);
  assert.equal(bumpKind('4.17.20', '4.17.21'), 'patch');
  assert.equal(bumpKind('4.17.20', '4.18.0'), 'minor');
  assert.equal(bumpKind('4.17.20', '5.0.0'), 'major');
  assert.equal(bumpKind('4.17.20', '4.17.20'), 'none');
});

test('rule 1: policy-suppressed → ACCEPT_RISK', () => {
  const v = computeScaVerdict(base({ suppressed: true, suppressionReason: 'accepted in sca-policy.yml' }));
  assert.equal(v.verdict, 'ACCEPT_RISK');
  assert.match(v.reason, /accepted in sca-policy/);
});

test('rule 2: no fixed version → WAIT_FOR_PATCH', () => {
  assert.equal(computeScaVerdict(base({ fixedVersions: [] })).verdict, 'WAIT_FOR_PATCH');
});

test('rule 3: KEV + reachable + patch → AUTO_MERGE_PATCH; major → MANUAL_REVIEW', () => {
  assert.equal(computeScaVerdict(base({ kev: true })).verdict, 'AUTO_MERGE_PATCH');
  assert.equal(computeScaVerdict(base({ kev: true, fixedVersions: ['5.0.0'] })).verdict, 'MANUAL_REVIEW');
});

test('rule 3 precedence: KEV but UNREACHABLE → falls through to ACCEPT_RISK', () => {
  const v = computeScaVerdict(base({ kev: true, reachabilityTier: 'unreachable' }));
  assert.equal(v.verdict, 'ACCEPT_RISK');
  assert.equal(v.expiryDays, 180);
});

test('rule 4/5: mitigated-in-prod (90d) and unreachable-in-prod/tier (180d) → ACCEPT_RISK', () => {
  assert.equal(computeScaVerdict(base({ mitigationVerdict: 'mitigated-in-prod' })).expiryDays, 90);
  assert.equal(computeScaVerdict(base({ reachabilityTier: 'transitive-only' })).expiryDays, 180);
});

test('rule 6/7: freeze and major bump → MANUAL_REVIEW', () => {
  assert.equal(computeScaVerdict(base({ majorVersionFrozen: true })).verdict, 'MANUAL_REVIEW');
  assert.equal(computeScaVerdict(base({ fixedVersions: ['5.0.0'] })).verdict, 'MANUAL_REVIEW');
});

test('rule 8: patch bump at high/critical risk → AUTO_MERGE_PATCH', () => {
  assert.equal(computeScaVerdict(base({ compositeRiskTier: 'high' })).verdict, 'AUTO_MERGE_PATCH');
  // patch bump at LOW risk does not auto-merge.
  assert.equal(computeScaVerdict(base({ compositeRiskTier: 'low' })).verdict, 'MANUAL_REVIEW');
});

test('rule 9: high EPSS + reachable + minor bump → AUTO_MERGE_PATCH', () => {
  const v = computeScaVerdict(base({ fixedVersions: ['4.18.0'], compositeRiskTier: 'medium', epssPercentile: 0.97 }));
  assert.equal(v.verdict, 'AUTO_MERGE_PATCH');
  assert.match(v.reason, /EPSS/);
});

test('rule 10: minor bump at critical risk with tests → AUTO_MERGE_PATCH', () => {
  const sc = base({ fixedVersions: ['4.18.0'], compositeRiskTier: 'critical' });
  assert.equal(computeScaVerdict(sc, { testsDetected: true }).verdict, 'AUTO_MERGE_PATCH');
  // Without tests, the same minor bump defers to human review.
  assert.equal(computeScaVerdict(sc, { testsDetected: false }).verdict, 'MANUAL_REVIEW');
});

test('rule 11: minor bump at non-critical risk → MANUAL_REVIEW', () => {
  assert.equal(computeScaVerdict(base({ fixedVersions: ['4.18.0'], compositeRiskTier: 'medium' })).verdict, 'MANUAL_REVIEW');
});

test('annotateScaVerdicts: sets fields + counts, skips non-deps', () => {
  const sca = [
    base({ kev: true }),                              // AUTO_MERGE_PATCH
    base({ fixedVersions: [] }),                      // WAIT_FOR_PATCH
    { type: 'unpinned_dep', name: 'x' },              // skipped
  ];
  annotateScaVerdicts(sca);
  assert.equal(sca[0].scaVerdict, 'AUTO_MERGE_PATCH');
  assert.equal(sca[1].scaVerdict, 'WAIT_FOR_PATCH');
  assert.equal(sca[2].scaVerdict, undefined);
  assert.equal(sca._scaVerdictCounts.AUTO_MERGE_PATCH, 1);
  assert.equal(sca._scaVerdictCounts.WAIT_FOR_PATCH, 1);
  // Every emitted verdict is in the closed enum.
  for (const s of sca) if (s.scaVerdict) assert.ok(SCA_VERDICTS.includes(s.scaVerdict));
});
