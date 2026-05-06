#!/usr/bin/env node
// PostToolUse hook: scan only the file(s) just edited; surface NEW high/critical findings.
// Throttled to ≤1 run per 5s per file to avoid storms during rapid edits.
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { runScan } from '../scanner/src/runScan.js';
import { normalizeFindings } from '../scanner/src/report/index.js';

async function readStdinJSON() {
  return new Promise((res) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => data += c);
    process.stdin.on('end', () => { try { res(JSON.parse(data || '{}')); } catch { res({}); } });
  });
}

const THROTTLE_MS = 5000;
const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const throttlePath = path.join(stateDir, 'hook-throttle.json');

function readThrottle() {
  try { return JSON.parse(fs.readFileSync(throttlePath, 'utf8')); } catch { return {}; }
}
function writeThrottle(t) {
  try { fs.mkdirSync(stateDir, { recursive: true }); fs.writeFileSync(throttlePath, JSON.stringify(t)); } catch {}
}

(async () => {
  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (!['Edit','Write','MultiEdit'].includes(tool)) process.exit(0);
  const file = evt.tool_input?.file_path || evt.tool_input?.filePath;
  if (!file) process.exit(0);
  const rel = path.relative(cwd, file);
  if (rel.startsWith('..')) process.exit(0);

  const throttle = readThrottle();
  const last = throttle[rel] || 0;
  const now = Date.now();
  if (now - last < THROTTLE_MS) process.exit(0);
  throttle[rel] = now;
  writeThrottle(throttle);

  // Scan just the parent dir for speed; engine will limit to the changed file via shouldScan
  const scanRoot = path.dirname(file);
  let findings;
  try {
    const { scan } = await runScan(scanRoot);
    findings = normalizeFindings(scan).filter(f => f.file && (f.file.endsWith(path.basename(file))) && (f.severity === 'critical' || f.severity === 'high'));
  } catch { process.exit(0); }

  // Compare against last-scan to surface only NEW high/critical findings on this file
  let baseline = new Set();
  try {
    const last = JSON.parse(fs.readFileSync(path.join(stateDir, 'last-scan.json'), 'utf8'));
    baseline = new Set(last.findings.filter(f => f.file && f.file.endsWith(path.basename(file))).map(f => f.id));
  } catch {}
  const fresh = findings.filter(f => !baseline.has(f.id));
  if (!fresh.length) process.exit(0);

  const notice = fresh.slice(0, 5).map(f => `  [${f.severity.toUpperCase()}] ${f.cwe||''} ${f.vuln} (${f.file}:${f.line})`).join('\n');
  const more = fresh.length > 5 ? `\n  ...and ${fresh.length - 5} more` : '';
  // Surface to Claude via stderr — the tool result includes hook output as additional context.
  console.error(`agentic-security: ${fresh.length} new high/critical finding(s) from this edit:\n${notice}${more}\n→ Run \`/security-fix-all --severity high\` to remediate.`);
  process.exit(0);
})();
