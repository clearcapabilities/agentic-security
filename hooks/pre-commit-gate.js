#!/usr/bin/env node
// PreToolUse hook for `git commit*`: block commits that add NEW critical findings vs. baseline.
// Override with AGENTIC_SECURITY_BYPASS=1.
import * as fs from 'node:fs';
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

(async () => {
  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (tool !== 'Bash') process.exit(0);
  const cmd = evt.tool_input?.command || '';
  if (!/\bgit\s+commit\b/.test(cmd)) process.exit(0);
  if (process.env.AGENTIC_SECURITY_BYPASS === '1') process.exit(0);

  const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const blPath = path.join(cwd, '.agentic-security', 'baseline.json');
  if (!fs.existsSync(blPath)) process.exit(0); // No baseline → don't block.

  let baselineIds;
  try {
    const baseline = JSON.parse(fs.readFileSync(blPath, 'utf8'));
    baselineIds = new Set(baseline.findings.map(f => f.id));
  } catch { process.exit(0); }

  let current;
  try {
    const { scan } = await runScan(cwd);
    current = normalizeFindings(scan);
  } catch { process.exit(0); }

  const newCritical = current.filter(f => f.severity === 'critical' && !baselineIds.has(f.id));
  if (!newCritical.length) process.exit(0);

  const lines = newCritical.slice(0, 10).map(f => `  [CRITICAL] ${f.cwe||''} ${f.vuln} (${f.file}:${f.line})`).join('\n');
  const more = newCritical.length > 10 ? `\n  ...and ${newCritical.length - 10} more` : '';
  // Exit code 2 with stderr → Claude Code blocks the tool call and shows reason.
  console.error(`agentic-security: ${newCritical.length} NEW critical finding(s) since baseline; commit blocked.\n${lines}${more}\n\nResolve via /security-fix-all --severity critical, or set AGENTIC_SECURITY_BYPASS=1 to override.`);
  process.exit(2);
})();
