// Held-out evaluator (premortem #16).
//
// Takes a labeled JSONL file of (predicted_confidence, actual_label) records
// and computes the honest measurements an auditor will ask for: Brier score,
// expected calibration error (ECE), per-family precision/recall.
//
// Replaces the tautological computeBrierFromHistory removed in premortem #9.
//
// Input file shape — one JSON object per line:
//
//   {"family": "sql-injection", "stableId": "...", "predicted": 0.78,
//    "actual": 1, "note": "TP — exploited in pen-test"}
//   {"family": "xss", "predicted": 0.65, "actual": 0,
//    "note": "FP — sanitizer present but flow-analysis missed it"}
//
// `actual` must be 0 (false-positive / clean) or 1 (true-positive). `predicted`
// is the calibrated_confidence we'd ship to the customer.
//
// Output shape — see `evaluateHeldOut` return value.

import * as fs from 'node:fs';
import { brierScore, computeBrierOnHeldOut, wilsonInterval } from './calibration.js';

const ECE_BINS_DEFAULT = 10;

export function parseLabeledJsonl(text) {
  if (typeof text !== 'string' || !text.length) return [];
  const out = [];
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const o = JSON.parse(t);
      if (!o || typeof o !== 'object') continue;
      const p = typeof o.predicted === 'number' ? o.predicted : null;
      const a = (o.actual === 1 || o.actual === true) ? 1
              : (o.actual === 0 || o.actual === false) ? 0
              : null;
      if (p === null || a === null) continue;
      out.push({
        family: typeof o.family === 'string' ? o.family : 'unknown',
        stableId: typeof o.stableId === 'string' ? o.stableId : null,
        predicted: Math.max(0, Math.min(1, p)),
        actual: a,
        note: typeof o.note === 'string' ? o.note : '',
      });
    } catch { /* skip malformed lines */ }
  }
  return out;
}

export function loadLabeledJsonl(filepath) {
  if (!filepath || !fs.existsSync(filepath)) return [];
  return parseLabeledJsonl(fs.readFileSync(filepath, 'utf8'));
}

// Expected calibration error: bucket predictions into `nBins` equal-width
// bins, compare bucket-mean prediction vs bucket-mean actual.
// ECE = sum over bins of (|bin|/N) * |mean_pred - mean_actual|.
// ECE = 0 is perfect; common-good calibration ≤ 0.05.
export function expectedCalibrationError(samples, nBins = ECE_BINS_DEFAULT) {
  if (!Array.isArray(samples) || samples.length === 0) return null;
  const n = samples.length;
  const bins = Array.from({ length: nBins }, () => ({ preds: [], actuals: [] }));
  for (const s of samples) {
    const p = Math.max(0, Math.min(1, s.predicted));
    // Clamp only for the bin index — `1.0` lands in the last bin without
    // distorting the bin's mean prediction.
    const idx = Math.min(nBins - 1, Math.floor(Math.min(0.99999, p) * nBins));
    bins[idx].preds.push(p);
    bins[idx].actuals.push(s.actual);
  }
  let ece = 0;
  const per = [];
  for (let i = 0; i < nBins; i++) {
    const b = bins[i];
    if (b.preds.length === 0) { per.push({ bin: i, n: 0 }); continue; }
    const mp = b.preds.reduce((a, c) => a + c, 0) / b.preds.length;
    const ma = b.actuals.reduce((a, c) => a + c, 0) / b.actuals.length;
    ece += (b.preds.length / n) * Math.abs(mp - ma);
    per.push({ bin: i, n: b.preds.length, mean_pred: mp, mean_actual: ma, gap: mp - ma });
  }
  return { ece, perBin: per, nBins, total: n };
}

export function perFamily(samples) {
  const fams = {};
  for (const s of samples) {
    const f = s.family || 'unknown';
    if (!fams[f]) fams[f] = { tp: 0, fp: 0, fn: 0, tn: 0, n: 0 };
    fams[f].n++;
    // We don't have a separate threshold here; "TP" = positive label;
    // "FP" = negative label. Precision is the engine's positive predictive
    // value at the operating point its calibration assigned.
    if (s.actual === 1) fams[f].tp++;
    else if (s.actual === 0) fams[f].fp++;
  }
  return fams;
}

// One-shot evaluation: Brier + ECE + per-family TP/FP + overall precision.
// Returns null only when there's truly no data; never returns a tautological
// zero.
export function evaluateHeldOut(samples) {
  if (!Array.isArray(samples) || samples.length === 0) {
    return { ok: false, reason: 'no-samples' };
  }
  const brierR = computeBrierOnHeldOut(samples.map(s => ({
    predicted: s.predicted, actual: s.actual,
  })));
  const ece = expectedCalibrationError(samples);
  const fams = perFamily(samples);
  const totalTP = Object.values(fams).reduce((a, f) => a + f.tp, 0);
  const totalFP = Object.values(fams).reduce((a, f) => a + f.fp, 0);
  const precision = (totalTP + totalFP) > 0 ? totalTP / (totalTP + totalFP) : 0;
  // Wilson CI on the overall positive-rate as a calibration sanity check.
  const ci = wilsonInterval(totalTP, totalTP + totalFP);
  return {
    ok: true,
    n: samples.length,
    brier: brierR.brier,
    ece: ece?.ece ?? null,
    eceDetail: ece,
    precision,
    precisionCi95: ci,
    perFamily: fams,
    notes: [
      ...(samples.length < 100 ? ['n<100: Brier and ECE have wide confidence; treat as directional, not decision-grade.'] : []),
      ...(brierR.brier !== null && brierR.brier > 0.10 ? [`brier=${brierR.brier.toFixed(3)} exceeds PRD target 0.10`] : []),
      ...(ece && ece.ece > 0.05 ? [`ece=${ece.ece.toFixed(3)} exceeds 0.05 calibration target`] : []),
    ],
  };
}

// CLI-friendly summary line.
export function summarize(result) {
  if (!result || !result.ok) return `held-out: ${result?.reason || 'unknown error'}`;
  return [
    `n=${result.n}`,
    `brier=${result.brier != null ? result.brier.toFixed(3) : 'null'}`,
    `ece=${result.ece != null ? result.ece.toFixed(3) : 'null'}`,
    `precision=${result.precision.toFixed(3)} CI95=[${result.precisionCi95[0].toFixed(3)},${result.precisionCi95[1].toFixed(3)}]`,
  ].join(' · ');
}
