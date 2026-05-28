#!/usr/bin/env node
// Top-N finding clusters per language. Reads findings.jsonl.
//
// A "cluster" is a (family, vuln, severity) tuple — same rule firing in many
// places. Clusters with very high counts on real OSS code are the highest-
// leverage FP-reduction targets: fixing one rule's matcher closes the whole
// cluster.
//
// Output capped at top-20 per language so the reviewer is bounded to a few
// hours of triage per cycle.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';

const DEFAULT_TOP_N = 20;
const SAMPLE_PER_CLUSTER = 3;

export async function cluster(cycleDir, opts = {}) {
  const findingsPath = path.join(cycleDir, 'findings.jsonl');
  const topN = opts.topN || DEFAULT_TOP_N;
  const perLang = {}; // lang -> Map<key, { count, family, vuln, severity, samples[] }>

  const stream = createReadStream(findingsPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (row.status !== 'ok') continue;
    const langMap = (perLang[row.lang] ??= new Map());
    for (const f of row.findings || []) {
      const key = `${f.family || '?'}|${f.vuln || '?'}|${f.severity || '?'}`;
      let entry = langMap.get(key);
      if (!entry) {
        entry = { count: 0, family: f.family, vuln: f.vuln, severity: f.severity, samples: [] };
        langMap.set(key, entry);
      }
      entry.count++;
      if (entry.samples.length < SAMPLE_PER_CLUSTER) {
        entry.samples.push({ path: row.path, line: f.line });
      }
    }
  }

  const report = { perLang: {} };
  for (const [lang, langMap] of Object.entries(perLang)) {
    const sorted = Array.from(langMap.values()).sort((a,b) => b.count - a.count);
    report.perLang[lang] = sorted.slice(0, topN);
  }
  return report;
}

function printTable(report, topN) {
  const langs = Object.keys(report.perLang).sort();
  for (const lang of langs) {
    const clusters = report.perLang[lang];
    if (!clusters.length) continue;
    console.log('');
    console.log(`=== ${lang} — top ${Math.min(topN, clusters.length)} finding clusters ===`);
    for (const c of clusters) {
      console.log(`  ${String(c.count).padStart(6)}× [${c.severity}] ${c.family} :: ${c.vuln}`);
      for (const s of c.samples) console.log(`         ↳ ${s.path}:${s.line}`);
    }
  }
  console.log('');
  console.log(`Triage rule: clusters firing in many real OSS files are FP candidates.`);
  console.log(`Sanity-check the samples; if 2 of 3 look like FPs, the cluster likely is one.`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const cycleDir = args.find(a => !a.startsWith('--'));
  if (!cycleDir) { console.error('Usage: cluster.mjs <cycleDir> [--top-n N] [--json]'); process.exit(2); }
  const idx = args.indexOf('--top-n');
  const topN = idx >= 0 ? parseInt(args[idx + 1], 10) : DEFAULT_TOP_N;
  const isJson = args.includes('--json');
  cluster(cycleDir, { topN }).then(r => {
    if (isJson) console.log(JSON.stringify(r, null, 2));
    else printTable(r, topN);
  }).catch(e => { console.error(e); process.exit(1); });
}
