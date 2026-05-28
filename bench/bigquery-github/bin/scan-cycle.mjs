#!/usr/bin/env node
// Per-file scan loop with per-file timeout + crash isolation.
//
// Reads cycle-<date>/files-index.jsonl, invokes runScan once per file with
// opts.fileContents = { [path]: content }, and writes one JSONL line per file
// to cycle-<date>/findings.jsonl with shape:
//
//   { file_id, lang, path, sha256,
//     status: "ok" | "timeout" | "crash",
//     elapsed_ms,
//     findings: [{ family, vuln, severity, line, ruleId? }, ...],  // ok only
//     error?: string,                                              // timeout/crash
//   }
//
// Blind mode (AGENTIC_SECURITY_BLIND_BENCH=1) is forced on so corpus-shape
// gates in the engine cannot bias the run. There are no FLAW markers in real
// OSS code to strip; the blinder's corpus-marker passes are no-ops here.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';
import { runScan } from '../../../scanner/src/runScan.js';

const DEFAULT_TIMEOUT_MS = 30000;

function withTimeout(promise, ms, label) {
  let to;
  const timeout = new Promise((_, reject) => {
    to = setTimeout(() => reject(new Error(`timeout after ${ms}ms (${label})`)), ms);
  });
  return Promise.race([promise.finally(() => clearTimeout(to)), timeout]);
}

function summarizeFindings(scan) {
  const out = [];
  const families = [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []),
  ];
  for (const f of families) {
    out.push({
      family: f.family || null,
      vuln: f.vuln || null,
      severity: f.severity || null,
      line: f.sink?.line ?? f.line ?? f.source?.line ?? null,
      ruleId: f.id || f.ruleId || null,
    });
  }
  return out;
}

export async function scanCycle(cycleDir, opts = {}) {
  const indexPath = path.join(cycleDir, 'files-index.jsonl');
  const outPath = path.join(cycleDir, 'findings.jsonl');
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const resume = !!opts.resume;

  // Force blind mode. This is real OSS code; we do not want any corpus-shape
  // code path firing on filename or path coincidences.
  process.env.AGENTIC_SECURITY_BLIND_BENCH = '1';
  delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;

  // For --resume: collect file_ids already in findings.jsonl so we can skip them.
  const done = new Set();
  if (resume) {
    try {
      const existing = createReadStream(outPath, { encoding: 'utf8' });
      const rl = readline.createInterface({ input: existing, crlfDelay: Infinity });
      for await (const line of rl) {
        if (!line.trim()) continue;
        try { done.add(JSON.parse(line).file_id); } catch {}
      }
    } catch { /* no prior run */ }
  }

  const out = await fs.open(outPath, resume ? 'a' : 'w');
  const counters = {
    scanned: 0, ok: 0, timeout: 0, crash: 0, skipped_done: 0,
    perLang: {}, // lang → { ok, timeout, crash, findings, totalLines, elapsedMs[] }
  };

  const stream = createReadStream(indexPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (!line.trim()) continue;
      let row;
      try { row = JSON.parse(line); } catch { continue; }
      if (done.has(row.file_id)) { counters.skipped_done++; continue; }

      const abs = path.join(cycleDir, row.materialized);
      let content;
      try { content = await fs.readFile(abs, 'utf8'); } catch { continue; }

      const fc = { [row.path]: content };
      const t0 = Date.now();
      const langStats = (counters.perLang[row.lang] ??= { ok: 0, timeout: 0, crash: 0, findings: 0, totalLines: 0, elapsedMs: [] });
      const lines = (content.match(/\n/g) || []).length + 1;
      langStats.totalLines += lines;

      let record;
      try {
        const { scan } = await withTimeout(runScan(cycleDir, { fileContents: fc }), timeoutMs, row.path);
        const findings = summarizeFindings(scan);
        record = {
          file_id: row.file_id, lang: row.lang, path: row.path,
          sha256: row.sha256, status: 'ok',
          elapsed_ms: Date.now() - t0,
          lines, findings,
        };
        langStats.ok++;
        langStats.findings += findings.length;
        counters.ok++;
      } catch (e) {
        const isTimeout = /^timeout after/.test(e?.message || '');
        record = {
          file_id: row.file_id, lang: row.lang, path: row.path,
          sha256: row.sha256, status: isTimeout ? 'timeout' : 'crash',
          elapsed_ms: Date.now() - t0,
          lines,
          error: e?.message?.slice(0, 500) || String(e).slice(0, 500),
        };
        if (isTimeout) { langStats.timeout++; counters.timeout++; }
        else            { langStats.crash++;   counters.crash++;   }
      }
      langStats.elapsedMs.push(record.elapsed_ms);
      await out.write(JSON.stringify(record) + '\n');
      counters.scanned++;

      if (counters.scanned % 100 === 0) {
        process.stderr.write(`  scanned ${counters.scanned} (ok=${counters.ok} timeout=${counters.timeout} crash=${counters.crash})\n`);
      }
    }
  } finally {
    await out.close();
  }

  // Per-language summary
  const summary = { totals: counters, perLang: {} };
  for (const [lang, s] of Object.entries(counters.perLang)) {
    const sorted = s.elapsedMs.slice().sort((a,b) => a-b);
    const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
    summary.perLang[lang] = {
      ok: s.ok, timeout: s.timeout, crash: s.crash,
      findings: s.findings, totalLines: s.totalLines,
      findingsPerKloc: s.totalLines > 0 ? (s.findings / (s.totalLines / 1000)) : 0,
      p50Ms: p50, p95Ms: p95,
    };
  }
  // Drop the elapsedMs arrays from the persisted summary so it stays small.
  delete summary.totals.perLang;
  await fs.writeFile(path.join(cycleDir, 'scan-summary.json'), JSON.stringify(summary, null, 2));
  process.stderr.write(`scan-cycle done: ${counters.scanned} files, ${counters.timeout} timeouts, ${counters.crash} crashes\n`);
  return summary;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const cycleDir = args.find(a => !a.startsWith('--'));
  if (!cycleDir) {
    console.error('Usage: scan-cycle.mjs <cycleDir> [--resume] [--timeout-ms N]');
    process.exit(2);
  }
  const idx = args.indexOf('--timeout-ms');
  const timeoutMs = idx >= 0 ? parseInt(args[idx + 1], 10) : DEFAULT_TIMEOUT_MS;
  const resume = args.includes('--resume');
  scanCycle(cycleDir, { timeoutMs, resume }).catch(e => { console.error(e); process.exit(1); });
}
