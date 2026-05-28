#!/usr/bin/env node
// End-to-end orchestrator for a single bench cycle.
//
// Modes:
//   --smoke                              Run the bundled self-test corpus
//   --all <ndjson>                       Materialize, scan, and score
//   --materialize <ndjson>               Materialize only
//   --scan                               Scan only (cycle must already be materialized)
//   --score                              Score only (cycle must already have findings.jsonl)
//
// Output goes to cycle-<YYYY-MM-DD>/ under the bench dir. The whole cycle dir
// is gitignored.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { materialize } from '../ingest/materialize.mjs';
import { scanCycle } from './scan-cycle.mjs';
import { fpDensity } from '../score/fp-density.mjs';
import { stability } from '../score/stability.mjs';
import { cluster } from '../score/cluster.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BENCH_ROOT = path.resolve(__dirname, '..');
const SELF_TEST_NDJSON = path.join(BENCH_ROOT, '_self-test', 'corpus.ndjson');
const REPO_ROOT = path.resolve(BENCH_ROOT, '..', '..');

function todayStamp() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
}

async function fileSha256(p) {
  try {
    const buf = await fs.readFile(p);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch { return null; }
}

async function gitSha() {
  try {
    const cp = await import('node:child_process');
    return cp.execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch { return null; }
}

async function writeManifest(cycleDir, sampleCounters) {
  const querySha = await fileSha256(path.join(BENCH_ROOT, 'query', 'stratified.sql'));
  const engineSha = await gitSha();
  const pkg = JSON.parse(await fs.readFile(path.join(REPO_ROOT, 'scanner', 'package.json'), 'utf8'));
  const manifest = {
    cycle: {
      date: todayStamp(),
      engine_version: pkg.version,
      engine_sha: engineSha,
      blind_mode: true,
      per_file_timeout_ms: 30000,
    },
    query: {
      sha: querySha,
      // bq_table_last_modified would come from `bq show --format=json …`;
      // populate manually when running production cycles.
      bq_table_last_modified: null,
    },
    sample: {
      total_files: sampleCounters.written,
      per_language: sampleCounters.perLang,
      per_stratum: sampleCounters.perStratum,
    },
    files_index: 'files-index.jsonl',
  };
  await fs.writeFile(path.join(cycleDir, 'manifest.yml'), toYaml(manifest));
}

// Tiny YAML emitter — manifest shape only. Avoid an npm dep on js-yaml here
// since this harness is otherwise zero-dep.
function toYaml(obj, depth = 0) {
  const pad = '  '.repeat(depth);
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'string') {
    if (/[:#\n]/.test(obj) || obj === '') return JSON.stringify(obj);
    return obj;
  }
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) {
    if (!obj.length) return '[]';
    return obj.map(x => `\n${pad}- ${toYaml(x, depth + 1).replace(/^\n/, '')}`).join('');
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj);
    if (!keys.length) return '{}';
    return keys.map(k => {
      const v = toYaml(obj[k], depth + 1);
      if (v.startsWith('\n')) return `\n${pad}${k}:${v}`;
      return `\n${pad}${k}: ${v}`;
    }).join('') + (depth === 0 ? '\n' : '');
  }
  return JSON.stringify(obj);
}

async function writeSummary(cycleDir, fp, stab, clus) {
  const lines = [];
  lines.push(`# Cycle ${path.basename(cycleDir)} — aggregate summary`);
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('## Findings density (per 1000 LoC)');
  lines.push('');
  lines.push('| Language | Files | kLoC | Findings | per-kLoC | Severity mix |');
  lines.push('|---|---:|---:|---:|---:|---|');
  for (const [lang, s] of Object.entries(fp.perLang).sort()) {
    const sev = ['critical','high','medium','low','info']
      .filter(k => s.perSeverity[k]).map(k => `${k[0]}:${s.perSeverity[k]}`).join(' ');
    lines.push(`| ${lang} | ${s.files} | ${s.kloc} | ${s.findings} | ${s.findingsPerKloc} | ${sev || '-'} |`);
  }
  lines.push('');
  lines.push('## Stability + latency');
  lines.push('');
  lines.push('| Language | Total | OK | Timeout | Crash | p50 ms | p95 ms | p99 ms |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|---:|');
  for (const [lang, s] of Object.entries(stab.perLang).sort()) {
    lines.push(`| ${lang} | ${s.total} | ${s.ok} | ${s.timeout} | ${s.crash} | ${s.p50Ms} | ${s.p95Ms} | ${s.p99Ms} |`);
  }
  lines.push('');
  lines.push('## Top finding clusters (FP candidates)');
  lines.push('');
  for (const [lang, cs] of Object.entries(clus.perLang).sort()) {
    if (!cs.length) continue;
    lines.push(`### ${lang}`);
    lines.push('');
    for (const c of cs.slice(0, 10)) {
      lines.push(`- **${c.count}×** [${c.severity}] \`${c.family}\` — ${c.vuln}`);
    }
    lines.push('');
  }
  lines.push('---');
  lines.push('');
  lines.push('**Per-file findings and source live under `findings.jsonl` and `files/` — gitignored. Do NOT publish.**');
  await fs.writeFile(path.join(cycleDir, 'summary.md'), lines.join('\n'));
}

async function main() {
  const args = process.argv.slice(2);
  const SMOKE = args.includes('--smoke');
  const ALL = args.includes('--all');
  const MAT  = args.includes('--materialize');
  const SCAN = args.includes('--scan');
  const SCORE = args.includes('--score');
  const cycleArgIdx = args.indexOf('--cycle');
  const cycleArg = cycleArgIdx >= 0 ? args[cycleArgIdx + 1] : null;
  const ndjsonArg = [ALL, MAT].some(Boolean) ? args[Math.max(args.indexOf('--all'), args.indexOf('--materialize')) + 1] : null;

  const cycleDir = cycleArg
    ? path.resolve(cycleArg)
    : path.join(BENCH_ROOT, `cycle-${todayStamp()}${SMOKE ? '-smoke' : ''}`);
  await fs.mkdir(cycleDir, { recursive: true });
  process.stderr.write(`cycle dir: ${cycleDir}\n`);

  let counters = null;
  if (SMOKE) {
    process.stderr.write(`smoke mode — using bundled self-test corpus\n`);
    counters = await materialize(SELF_TEST_NDJSON, cycleDir);
    await writeManifest(cycleDir, counters);
    await scanCycle(cycleDir);
  } else if (ALL || MAT) {
    if (!ndjsonArg) { console.error('Missing NDJSON path. Usage: --all <ndjson> | --materialize <ndjson>'); process.exit(2); }
    counters = await materialize(ndjsonArg, cycleDir);
    await writeManifest(cycleDir, counters);
    if (ALL) await scanCycle(cycleDir);
  } else if (SCAN) {
    await scanCycle(cycleDir);
  } else if (!SCORE) {
    console.error('Usage:');
    console.error('  run-cycle.mjs --smoke');
    console.error('  run-cycle.mjs --all <ndjson>');
    console.error('  run-cycle.mjs --materialize <ndjson>');
    console.error('  run-cycle.mjs --scan [--cycle <dir>]');
    console.error('  run-cycle.mjs --score [--cycle <dir>]');
    process.exit(2);
  }

  // Score whenever findings.jsonl exists (i.e. after --all, --smoke, --scan, --score).
  const findingsPath = path.join(cycleDir, 'findings.jsonl');
  try { await fs.access(findingsPath); }
  catch {
    process.stderr.write(`no findings.jsonl at ${findingsPath}; skipping score\n`);
    return;
  }
  const [fp, stab, clus] = await Promise.all([
    fpDensity(cycleDir),
    stability(cycleDir),
    cluster(cycleDir),
  ]);
  await writeSummary(cycleDir, fp, stab, clus);
  process.stderr.write(`\nsummary written: ${path.join(cycleDir, 'summary.md')}\n`);
  console.log(JSON.stringify({ cycleDir, fpDensity: fp, stability: stab, cluster: clus }, null, 2));
}

main().catch(e => { console.error(e); process.exit(1); });
