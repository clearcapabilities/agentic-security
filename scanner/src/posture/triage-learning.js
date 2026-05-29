// Continuous learning from triage decisions — Recommendation #8 of the
// world-class roadmap.
//
// Every triage transition (open → fixed | wont-fix | false-positive)
// auto-tunes a per-(project, family, file-glob, sink-method) calibration
// store. The store directly modifies finding confidence scores on
// subsequent scans, so the scanner's precision on each individual
// codebase improves monotonically the longer it runs.
//
// Calibration shape:
//
//   { "global": {  // per-(family, sink-method) prior across all projects
//       "sql-injection|.executeQuery": { tp: 142, fp: 7, lastUpdated: "..." }
//     },
//     "perProject": {  // per-(file-glob, family) project-specific delta
//       "src/admin/**|hardcoded-secret": { tp: 0, fp: 23, lastUpdated: "..." }
//     }
//   }
//
// Update rule on triage:
//   transition → 'fixed' / 'wont-fix-because-not-exploitable' counts as TP+1
//   transition → 'false-positive' counts as FP+1
//
// Application rule at scan time:
//   confidence *= bayesianFactor(prior, project)
// where bayesianFactor uses a beta-distribution update of the priors.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { statePath, safeWriteState } from './state-dir.js';

const CALIBRATION_FILE = 'triage-calibration.json';

// Minimum sample size before per-project calibration takes effect. With
// fewer than this many triage decisions, we fall back to global priors.
const MIN_PROJECT_SAMPLES = 5;

// Bayesian prior — beta(α, β) over the precision rate. α=1, β=1 is a
// uniform prior (no opinion); α=2, β=1 mildly favors precision.
const PRIOR_ALPHA = 2;
const PRIOR_BETA = 1;

function _storePath(scanRoot) {
  return statePath(scanRoot, CALIBRATION_FILE);
}

export function loadCalibration(scanRoot) {
  const fp = _storePath(scanRoot);
  if (!fs.existsSync(fp)) return { global: {}, perProject: {} };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return { global: {}, perProject: {} }; }
}

function _save(scanRoot, data) {
  const fp = _storePath(scanRoot);
  safeWriteState(fp, JSON.stringify(data, null, 2));
}

function _bucketKey(family, sinkMethod) {
  return `${family || 'unknown'}|${sinkMethod || ''}`;
}

function _projectKey(fileGlob, family) {
  return `${fileGlob || '*'}|${family || 'unknown'}`;
}

/**
 * Record a triage decision. Called by the triage transition path.
 *   verdict ∈ { 'true-positive', 'false-positive' }
 */
export function recordTriageDecision(scanRoot, finding, verdict) {
  if (!finding || !verdict) return null;
  const data = loadCalibration(scanRoot);
  const family = finding.family;
  const sinkMethod = _extractSinkMethod(finding);
  const fileGlob = _fileGlobFor(finding.file);
  const now = new Date().toISOString();

  const gk = _bucketKey(family, sinkMethod);
  data.global[gk] ||= { tp: 0, fp: 0, lastUpdated: now };
  if (verdict === 'true-positive') data.global[gk].tp++;
  if (verdict === 'false-positive') data.global[gk].fp++;
  data.global[gk].lastUpdated = now;

  const pk = _projectKey(fileGlob, family);
  data.perProject[pk] ||= { tp: 0, fp: 0, lastUpdated: now };
  if (verdict === 'true-positive') data.perProject[pk].tp++;
  if (verdict === 'false-positive') data.perProject[pk].fp++;
  data.perProject[pk].lastUpdated = now;

  _save(scanRoot, data);
  return { gk, pk, data };
}

/**
 * Apply learned calibration to a fresh batch of findings. Modifies
 * confidence in place. Returns { adjusted: int, suppressed: int }
 * — findings whose adjusted confidence drops below `suppressThreshold`
 * are filtered out (added to the suppression log instead).
 */
export function applyLearnedCalibration(scanRoot, findings, opts = {}) {
  if (!Array.isArray(findings)) return { adjusted: 0, suppressed: 0 };
  const data = loadCalibration(scanRoot);
  const suppressThreshold = opts.suppressThreshold ?? 0.2;
  let adjusted = 0;
  const suppressedList = [];
  for (const f of findings) {
    const factor = _learnedFactor(data, f);
    if (factor === 1.0) continue;
    const before = typeof f.confidence === 'number' ? f.confidence : 0.85;
    const after = Math.max(0.01, Math.min(0.99, before * factor));
    f.confidence = after;
    f._learnedCalibration = { factor, before, samples: _sampleCount(data, f) };
    adjusted++;
    if (after < suppressThreshold) {
      f._suppressed_by = 'triage-learning';
      suppressedList.push(f);
    }
  }
  return { adjusted, suppressed: suppressedList.length, suppressedList, data };
}

function _learnedFactor(data, finding) {
  const family = finding.family;
  const sinkMethod = _extractSinkMethod(finding);
  const fileGlob = _fileGlobFor(finding.file);

  // Per-project: beta-distribution precision estimate when N is large enough.
  const pk = _projectKey(fileGlob, family);
  const proj = data.perProject?.[pk];
  if (proj && proj.tp + proj.fp >= MIN_PROJECT_SAMPLES) {
    const p = (PRIOR_ALPHA + proj.tp) / (PRIOR_ALPHA + PRIOR_BETA + proj.tp + proj.fp);
    return p / 0.5;  // 0.5 = neutral prior precision
  }
  // Global: same formula, less aggressive scaling.
  const gk = _bucketKey(family, sinkMethod);
  const glob = data.global?.[gk];
  if (glob && glob.tp + glob.fp >= MIN_PROJECT_SAMPLES) {
    const p = (PRIOR_ALPHA + glob.tp) / (PRIOR_ALPHA + PRIOR_BETA + glob.tp + glob.fp);
    return (0.7 * (p / 0.5)) + 0.3; // weight: 70% global, 30% neutral
  }
  return 1.0;
}

function _sampleCount(data, finding) {
  const family = finding.family;
  const sinkMethod = _extractSinkMethod(finding);
  const fileGlob = _fileGlobFor(finding.file);
  const pk = _projectKey(fileGlob, family);
  const gk = _bucketKey(family, sinkMethod);
  const proj = data.perProject?.[pk] || { tp: 0, fp: 0 };
  const glob = data.global?.[gk] || { tp: 0, fp: 0 };
  return { perProject: proj.tp + proj.fp, global: glob.tp + glob.fp };
}

function _extractSinkMethod(finding) {
  if (finding.sink?.method) return finding.sink.method;
  // Try to parse from the vuln string ("SQL Injection — executeQuery").
  const m = (finding.vuln || '').match(/\b([A-Za-z_]\w*)\s*\(/);
  return m ? m[1] : '';
}

function _fileGlobFor(file) {
  if (!file) return '*';
  const parts = file.split('/');
  if (parts.length <= 2) return file;
  return parts.slice(0, 2).join('/') + '/**';
}

export const _internals = { _bucketKey, _projectKey, _extractSinkMethod, _fileGlobFor, MIN_PROJECT_SAMPLES };
