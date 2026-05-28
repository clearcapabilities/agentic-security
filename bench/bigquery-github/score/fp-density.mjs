#!/usr/bin/env node
// Per-language findings-per-KLoC aggregator. Reads cycle-<date>/findings.jsonl
// and emits a per-language table.
//
// Real OSS code is overwhelmingly clean: most files have zero true vulns.
// So findings-per-KLoC is a proxy for false-positive density. High numbers
// indicate either (a) a noisy detector, (b) the corpus skewed toward
// security-relevant code, or (c) real bugs at unusual concentration.
// Stage 3 (cluster.mjs) is required to distinguish (a) from (c).

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';

export async function fpDensity(cycleDir) {
  const findingsPath = path.join(cycleDir, 'findings.jsonl');
  const perLang = {}; // lang -> { files, lines, findings, perSeverity }

  const stream = createReadStream(findingsPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (row.status !== 'ok') continue;

    const s = (perLang[row.lang] ??= { files: 0, lines: 0, findings: 0, perSeverity: {} });
    s.files++;
    s.lines += row.lines || 0;
    s.findings += (row.findings || []).length;
    for (const f of row.findings || []) {
      const sev = f.severity || 'unknown';
      s.perSeverity[sev] = (s.perSeverity[sev] || 0) + 1;
    }
  }

  const report = { perLang: {} };
  for (const [lang, s] of Object.entries(perLang)) {
    report.perLang[lang] = {
      files: s.files,
      kloc: +(s.lines / 1000).toFixed(1),
      findings: s.findings,
      findingsPerKloc: s.lines > 0 ? +(s.findings / (s.lines / 1000)).toFixed(3) : 0,
      perSeverity: s.perSeverity,
    };
  }
  return report;
}

function printTable(report) {
  const langs = Object.keys(report.perLang).sort();
  console.log('');
  console.log(`Findings density (per 1000 LoC), blind-mode scan against real-world OSS sample:`);
  console.log('');
  console.log(`${'lang'.padEnd(12)} ${'files'.padStart(6)} ${'kLoC'.padStart(8)} ${'finds'.padStart(7)} ${'per-kLoC'.padStart(9)}   severity-mix`);
  console.log(`${'-'.repeat(12)} ${'------'} ${'--------'} ${'-------'} ${'---------'}   ${'-'.repeat(40)}`);
  for (const lang of langs) {
    const s = report.perLang[lang];
    const sev = ['critical','high','medium','low','info']
      .filter(k => s.perSeverity[k])
      .map(k => `${k[0]}:${s.perSeverity[k]}`).join(' ');
    console.log(`${lang.padEnd(12)} ${String(s.files).padStart(6)} ${String(s.kloc).padStart(8)} ${String(s.findings).padStart(7)} ${String(s.findingsPerKloc).padStart(9)}   ${sev}`);
  }
  console.log('');
  console.log(`NOTE: high per-kLoC numbers are FP candidates, not confirmed bugs.`);
  console.log(`Inspect top finding clusters via score/cluster.mjs to triage.`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cycleDir, ...rest] = process.argv.slice(2);
  if (!cycleDir) { console.error('Usage: fp-density.mjs <cycleDir> [--json]'); process.exit(2); }
  const isJson = rest.includes('--json');
  fpDensity(cycleDir).then(r => {
    if (isJson) console.log(JSON.stringify(r, null, 2));
    else printTable(r);
  }).catch(e => { console.error(e); process.exit(1); });
}
