// Calibrated confidence tests (P1.3 / FR-UX-1, FR-UX-2).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  wilsonInterval,
  brierScore,
  buildCalibrationTable,
  annotateCalibratedConfidence,
  computeBrierOnHeldOut,
  _internals,
} from '../src/posture/calibration.js';

test('wilsonInterval is symmetric around 0.5 with large N', () => {
  const [lo, hi] = wilsonInterval(500, 1000);
  assert.ok(Math.abs((lo + hi) / 2 - 0.5) < 0.005);
  assert.ok(hi - lo < 0.07);
});

test('wilsonInterval is wide on small N', () => {
  const [lo, hi] = wilsonInterval(1, 3);
  // n=3 → CI width should be > 0.4; we're not pretending to know the rate
  assert.ok(hi - lo > 0.4);
});

test('wilsonInterval handles 0 and 1 without NaN', () => {
  const [lo0, hi0] = wilsonInterval(0, 10);
  assert.equal(lo0, 0);
  assert.ok(hi0 > 0 && hi0 < 0.4);
  const [lo1, hi1] = wilsonInterval(10, 10);
  // hi1 should be ≥ 0.999 (might be 1 - 1e-16 due to FP).
  assert.ok(hi1 >= 0.999);
  assert.ok(lo1 > 0.6);
});

test('wilsonInterval returns [0,1] for n=0 (no data)', () => {
  assert.deepEqual(wilsonInterval(0, 0), [0, 1]);
});

test('brierScore = 0 for perfect predictions', () => {
  const s = [
    { prediction: 1, actual: 1 },
    { prediction: 0, actual: 0 },
    { prediction: 0.5, actual: 0.5 },
  ];
  assert.equal(brierScore(s), 0);
});

test('brierScore = 1 for always-wrong predictions', () => {
  const s = [{ prediction: 1, actual: 0 }, { prediction: 0, actual: 1 }];
  assert.equal(brierScore(s), 1);
});

test('brierScore returns null for empty input', () => {
  assert.equal(brierScore([]), null);
  assert.equal(brierScore(null), null);
});

test('buildCalibrationTable computes rate only when N >= MIN_SAMPLES_FOR_CALIBRATION', () => {
  const history = {
    families: {
      'sql-injection':   { tp: 40, fp: 4 },         // n=44, calibrated
      'rare-vuln':       { tp: 2,  fp: 1 },         // n=3,  null
      'borderline':      { tp: 28, fp: 1 },         // n=29, null (< 30)
      'just-enough':     { tp: 25, fp: 5 },         // n=30, calibrated
    },
  };
  const t = buildCalibrationTable(history);
  assert.ok(t['sql-injection'].calibrated > 0.9);
  assert.equal(t['rare-vuln'].calibrated, null);
  assert.equal(t['borderline'].calibrated, null);
  assert.ok(typeof t['just-enough'].calibrated === 'number');
  assert.equal(t['just-enough'].n, 30);
});

test('annotateCalibratedConfidence sets fields on findings', () => {
  const history = {
    families: { 'sql-injection': { tp: 40, fp: 4 } },
  };
  const findings = [
    { family: 'sql-injection', vuln: 'X' },
    { family: 'unmapped', vuln: 'Y' },
    { vuln: 'Z' },
  ];
  annotateCalibratedConfidence(findings, { history });
  assert.ok(findings[0].calibrated_confidence > 0.85);
  assert.ok(findings[0].calibrated_confidence_ci.length === 2);
  assert.equal(findings[0].calibrated_n, 44);
  assert.equal(findings[1].calibrated_confidence, null);
  assert.equal(findings[1].calibration_reason, 'no-history');
  assert.equal(findings[2].calibration_reason, 'no-family');
});

test('annotateCalibratedConfidence flags insufficient-samples when N < min', () => {
  const history = { families: { 'sql-injection': { tp: 5, fp: 0 } } };
  const findings = [{ family: 'sql-injection' }];
  annotateCalibratedConfidence(findings, { history });
  assert.equal(findings[0].calibrated_confidence, null);
  assert.equal(findings[0].calibration_reason, 'insufficient-samples');
  assert.equal(findings[0].calibrated_n, 5);
});

test('annotateCalibratedConfidence does not throw on null input', () => {
  assert.doesNotThrow(() => annotateCalibratedConfidence(null));
  assert.doesNotThrow(() => annotateCalibratedConfidence([null, undefined, 'string', 42]));
});

test('computeBrierOnHeldOut returns null for empty', () => {
  const r = computeBrierOnHeldOut([]);
  assert.equal(r.brier, null);
});
test('computeBrierOnHeldOut scores real predictions vs labels', () => {
  // Perfect predictions → Brier 0.
  const r0 = computeBrierOnHeldOut([
    { family: 'sql', predicted: 1, actual: 1 },
    { family: 'sql', predicted: 0, actual: 0 },
  ]);
  assert.ok(r0.brier !== null && r0.brier < 1e-9);
  // Always-wrong predictions → Brier 1.
  const r1 = computeBrierOnHeldOut([
    { family: 'sql', predicted: 1, actual: 0 },
    { family: 'sql', predicted: 0, actual: 1 },
  ]);
  assert.ok(r1.brier > 0.99);
});

test('seed corpus loads via loadCalibrationHistory + buildCalibrationTable', async () => {
  const { loadCalibrationHistory } = await import('../src/posture/calibration.js');
  const h = loadCalibrationHistory(process.cwd());
  // Seed includes SQL injection with calibrated samples — should be a real number.
  const t = buildCalibrationTable(h);
  assert.ok(t['sql-injection'], 'seed must include sql-injection');
  assert.ok(typeof t['sql-injection'].calibrated === 'number');
});

test('_internals reports the calibration floor', () => {
  assert.equal(_internals.MIN_SAMPLES_FOR_CALIBRATION, 30);
});
