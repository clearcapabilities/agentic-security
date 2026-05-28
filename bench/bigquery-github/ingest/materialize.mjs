#!/usr/bin/env node
// Materialize a BigQuery NDJSON dump into a cycle directory.
//
// Input: one JSON object per line, schema:
//   { stratum, repo_name, path, file_id, content, content_size, repo_license }
//
// Output:
//   cycle-<date>/files/<lang>/<repo_owner>__<repo_name>/<path>   ← source
//   cycle-<date>/files-index.jsonl                               ← {file_id, lang, path, sha256, size}
//   cycle-<date>/manifest.yml                                    ← per-cycle metadata
//
// Per-language directories pin the language label so the scanner cannot get
// confused about polyglot files (e.g. a .h header in a C++ project that the
// detector might mis-route).

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as readline from 'node:readline';
import { createReadStream } from 'node:fs';

const EXT_TO_LANG = {
  py: 'python',
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript',
  cs: 'csharp',
  c: 'cpp', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', h: 'cpp', hh: 'cpp', hpp: 'cpp', hxx: 'cpp',
  java: 'java',
  go: 'go',
  rb: 'ruby',
  php: 'php',
  kt: 'kotlin', kts: 'kotlin',
  swift: 'swift',
  rs: 'rust',
  sol: 'solidity',
  dart: 'dart',
};

function langFromPath(filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  return EXT_TO_LANG[ext] || null;
}

function sanitizeRepoName(repoName) {
  return repoName.replace(/[^A-Za-z0-9._-]/g, '_');
}

// Disk cap — refuse to write a cycle larger than this. Configurable per call.
const DEFAULT_DISK_CAP_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB

export async function materialize(ndjsonPath, cycleDir, opts = {}) {
  const filesDir = path.join(cycleDir, 'files');
  const indexPath = path.join(cycleDir, 'files-index.jsonl');
  const diskCap = opts.diskCapBytes || DEFAULT_DISK_CAP_BYTES;

  await fs.mkdir(filesDir, { recursive: true });
  const indexHandle = await fs.open(indexPath, 'w');

  const counters = { total: 0, written: 0, skipped: 0, perLang: {}, perStratum: {}, bytes: 0 };

  const stream = createReadStream(ndjsonPath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  try {
    for await (const line of rl) {
      counters.total++;
      if (!line.trim()) continue;
      let row;
      try { row = JSON.parse(line); }
      catch { counters.skipped++; continue; }

      const { stratum, repo_name, path: filePath, file_id, content, repo_license } = row;
      if (!filePath || !content || !file_id) { counters.skipped++; continue; }

      const lang = langFromPath(filePath);
      if (!lang) { counters.skipped++; continue; }

      // Disk cap guard.
      if (counters.bytes + content.length > diskCap) {
        process.stderr.write(`materialize: disk cap reached (${(diskCap/1e9).toFixed(1)} GB), stopping at ${counters.written} files\n`);
        break;
      }

      const dstDir = path.join(filesDir, lang, sanitizeRepoName(repo_name || 'unknown'));
      const dstFile = path.join(dstDir, filePath.replace(/^\/+/, ''));
      await fs.mkdir(path.dirname(dstFile), { recursive: true });
      await fs.writeFile(dstFile, content, 'utf8');

      const sha = crypto.createHash('sha256').update(content).digest('hex');
      await indexHandle.write(JSON.stringify({
        file_id, lang, stratum, repo_name, path: filePath,
        materialized: path.relative(cycleDir, dstFile),
        sha256: sha, size: content.length,
        license: repo_license || null,
      }) + '\n');

      counters.written++;
      counters.bytes += content.length;
      counters.perLang[lang] = (counters.perLang[lang] || 0) + 1;
      counters.perStratum[stratum || 'unknown'] = (counters.perStratum[stratum || 'unknown'] || 0) + 1;

      if (counters.written % 1000 === 0) {
        process.stderr.write(`  materialized ${counters.written} files (${(counters.bytes/1e6).toFixed(0)} MB)\n`);
      }
    }
  } finally {
    await indexHandle.close();
  }

  process.stderr.write(`materialize: ${counters.written} files written, ${counters.skipped} skipped, ${(counters.bytes/1e6).toFixed(0)} MB total\n`);
  return counters;
}

// CLI entry: materialize.mjs <ndjson> <cycleDir>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [ndjson, cycleDir] = process.argv.slice(2);
  if (!ndjson || !cycleDir) {
    console.error('Usage: materialize.mjs <ndjson> <cycleDir>');
    process.exit(2);
  }
  materialize(ndjson, cycleDir).catch(e => { console.error(e); process.exit(1); });
}
