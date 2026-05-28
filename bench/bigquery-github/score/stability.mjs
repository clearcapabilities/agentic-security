#!/usr/bin/env node
// Per-language crash + timeout + latency aggregator. Reads findings.jsonl.
//
// Crash rate is a binary signal — any non-zero rate per 10k files is a bug
// to fix, not a metric to optimize. Timeout rate above a threshold suggests
// pathological inputs (catastrophic regex, IR parser hangs). Latency p95
// gives a performance budget reference point.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';

export async function stability(cycleDir) {
  const findingsPath = path.join(cycleDir, 'findings.jsonl');
  const perLang = {}; // lang -> { total, ok, timeout, crash, errors[], elapsedMs[] }

  const stream = createReadStream(findingsPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }

    const s = (perLang[row.lang] ??= { total: 0, ok: 0, timeout: 0, crash: 0, errors: [], elapsedMs: [] });
    s.total++;
    if (row.status === 'ok') s.ok++;
    else if (row.status === 'timeout') { s.timeout++; if (s.errors.length < 5) s.errors.push({ path: row.path, error: row.error }); }
    else if (row.status === 'crash')   { s.crash++;   if (s.errors.length < 5) s.errors.push({ path: row.path, error: row.error }); }
    if (typeof row.elapsed_ms === 'number') s.elapsedMs.push(row.elapsed_ms);
  }

  const report = { perLang: {} };
  for (const [lang, s] of Object.entries(perLang)) {
    const sorted = s.elapsedMs.slice().sort((a,b) => a-b);
    const p = (q) => sorted[Math.floor(sorted.length * q)] || 0;
    report.perLang[lang] = {
      total: s.total, ok: s.ok, timeout: s.timeout, crash: s.crash,
      crashRatePer10k: s.total > 0 ? +(10000 * s.crash / s.total).toFixed(2) : 0,
      timeoutRatePer10k: s.total > 0 ? +(10000 * s.timeout / s.total).toFixed(2) : 0,
      p50Ms: p(0.5), p95Ms: p(0.95), p99Ms: p(0.99),
      sampleErrors: s.errors,
    };
  }
  return report;
}

function printTable(report) {
  const langs = Object.keys(report.perLang).sort();
  console.log('');
  console.log(`Stability + latency per language:`);
  console.log('');
  console.log(`${'lang'.padEnd(12)} ${'total'.padStart(6)} ${'ok'.padStart(6)} ${'to'.padStart(4)} ${'crash'.padStart(5)}   ${'p50'.padStart(6)} ${'p95'.padStart(6)} ${'p99'.padStart(7)} ms`);
  console.log(`${'-'.repeat(12)} ${'------'} ${'------'} ${'----'} ${'-----'}   ${'------'} ${'------'} ${'-------'}`);
  for (const lang of langs) {
    const s = report.perLang[lang];
    console.log(`${lang.padEnd(12)} ${String(s.total).padStart(6)} ${String(s.ok).padStart(6)} ${String(s.timeout).padStart(4)} ${String(s.crash).padStart(5)}   ${String(s.p50Ms).padStart(6)} ${String(s.p95Ms).padStart(6)} ${String(s.p99Ms).padStart(7)}`);
    if (s.sampleErrors.length) {
      for (const e of s.sampleErrors.slice(0, 2)) console.log(`            ↳ ${e.path}: ${e.error?.slice(0, 80) || ''}`);
    }
  }
  console.log('');
  console.log(`Any crash > 0 is a bug to fix, not a metric.`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cycleDir, ...rest] = process.argv.slice(2);
  if (!cycleDir) { console.error('Usage: stability.mjs <cycleDir> [--json]'); process.exit(2); }
  const isJson = rest.includes('--json');
  stability(cycleDir).then(r => {
    if (isJson) console.log(JSON.stringify(r, null, 2));
    else printTable(r);
  }).catch(e => { console.error(e); process.exit(1); });
}
