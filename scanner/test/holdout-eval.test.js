// Held-out evaluator tests (premortem #16).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseLabeledJsonl,
  expectedCalibrationError,
  evaluateHeldOut,
  summarize,
} from '../src/posture/holdout-eval.js';

test('parseLabeledJsonl skips malformed and bad-type lines', () => {
  const text = [
    '{"family":"sql","predicted":0.9,"actual":1}',
    'not json at all',
    '{"family":"xss","predicted":"bad","actual":0}',
    '{"family":"sql","predicted":0.1,"actual":0,"note":"FP"}',
    '',
  ].join('\n');
  const s = parseLabeledJsonl(text);
  assert.equal(s.length, 2);
  assert.equal(s[0].family, 'sql');
  assert.equal(s[1].predicted, 0.1);
});

test('expectedCalibrationError = 0 on perfect predictions', () => {
  const samples = [
    { predicted: 1.0, actual: 1 },
    { predicted: 1.0, actual: 1 },
    { predicted: 0.0, actual: 0 },
    { predicted: 0.0, actual: 0 },
  ];
  const r = expectedCalibrationError(samples, 5);
  assert.ok(r.ece < 1e-9);
});

test('expectedCalibrationError catches an over-confident classifier', () => {
  // Predicts 0.9 confidence but is wrong half the time → big gap in the 0.9 bin.
  const samples = [];
  for (let i = 0; i < 100; i++) samples.push({ predicted: 0.9, actual: i % 2 === 0 ? 1 : 0 });
  const r = expectedCalibrationError(samples, 10);
  assert.ok(r.ece > 0.35, `over-confident ECE should be huge, got ${r.ece}`);
});

test('evaluateHeldOut surfaces the PRD threshold breach in notes', () => {
  // Force brier > 0.10 by predicting 0.5 for items whose actual is always 1.
  // Brier = (0.5 - 1)^2 = 0.25 > 0.10.
  const samples = Array.from({ length: 50 }, () => ({ family: 'sql', predicted: 0.5, actual: 1 }));
  const r = evaluateHeldOut(samples);
  assert.equal(r.ok, true);
  assert.ok(r.brier > 0.20);
  assert.ok(r.notes.some(n => n.startsWith('brier=')));
  assert.ok(r.notes.some(n => /n<100/.test(n)));
});

test('summarize renders a one-line string', () => {
  const samples = [
    { family: 'sql', predicted: 0.9, actual: 1 },
    { family: 'sql', predicted: 0.1, actual: 0 },
  ];
  const r = evaluateHeldOut(samples);
  const s = summarize(r);
  assert.match(s, /^n=2 · brier=/);
  assert.match(s, /precision=/);
});

test('evaluateHeldOut returns ok:false with no samples', () => {
  const r = evaluateHeldOut([]);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-samples');
});
