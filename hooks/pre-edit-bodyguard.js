#!/usr/bin/env node
// PreToolUse hook: scan the content the agent is ABOUT to write, before it
// hits disk. Block (or warn) on critical patterns so insecure AI-generated
// code never lands.
//
// Behavior controlled by .agentic-security/bodyguard.json:
//   { "mode": "warn" | "block" | "off", "skipPaths": ["test/", "fixtures/"] }
// Default mode: "warn". Set "block" to fail the edit on critical findings.
//
// Plain CommonJS — zero deps. Reads the proposed content from the tool input
// payload, runs a fast in-memory subset of high-confidence rules, and either
// exits 0 (allow) or exits 2 with an explanation (block).
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const cfgPath = path.join(stateDir, 'bodyguard.json');

function readCfg() {
  try { return JSON.parse(fs.readFileSync(cfgPath, 'utf8')); }
  catch { return { mode: 'warn', skipPaths: ['test/', 'tests/', '__tests__/', 'fixtures/', 'node_modules/'] }; }
}

function readStdinJSON() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

// Fast in-memory rules — high-precision, low-FP patterns that vibe-coders
// most often ship unintentionally. The full scanner runs post-edit; this is
// the just-in-time gate for the obviously-dangerous stuff.
const RULES = [
  {
    id: 'sqli-string-concat',
    name: 'SQL injection (string concatenation)',
    severity: 'critical',
    re: /(?:db|connection|client|knex|pool|sequelize)\s*\.\s*(?:query|raw|execute)\s*\(\s*[`'"][^`'"]*\$\{|(?:db|connection|client)\s*\.\s*(?:query|raw|execute)\s*\(\s*['"][^'"]*['"]\s*\+\s*\w+/i,
    hint: 'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = ?", [id])` — never string-concat user input.',
  },
  {
    id: 'cmd-injection',
    name: 'Shell command injection',
    severity: 'critical',
    re: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*[`'"][^`'"]*\$\{|(?:os\.system|subprocess\.(?:call|run|Popen))\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*\+|.*\+\s*\w+)/,
    hint: 'Never interpolate user input into a shell string. Pass argv as an array: `spawn("ls", [userPath], {shell: false})`.',
  },
  {
    id: 'next-public-secret',
    name: 'Secret leaked to client (NEXT_PUBLIC_)',
    severity: 'critical',
    re: /NEXT_PUBLIC_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|API_KEY|ANTHROPIC|OPENAI|STRIPE_SECRET|SUPABASE_SERVICE)/i,
    hint: 'Anything prefixed `NEXT_PUBLIC_` ships to the browser. Move this to a non-public env var and access it only in a server route.',
  },
  {
    id: 'hardcoded-secret',
    name: 'Hardcoded credential',
    severity: 'critical',
    re: /(?:api[_-]?key|secret[_-]?key|password|access[_-]?token)\s*[:=]\s*['"`](?:sk-[A-Za-z0-9-]{20,}|ghp_[A-Za-z0-9]{30,}|xoxb-[A-Za-z0-9-]{30,}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}|pk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,})['"`]/i,
    hint: 'Move this credential to an env var (e.g. `process.env.OPENAI_API_KEY`) and add the value to .env (which must be in .gitignore).',
  },
  {
    id: 'dangerous-html',
    name: 'XSS via dangerouslySetInnerHTML',
    severity: 'high',
    re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitize)/,
    hint: 'Pass user input through DOMPurify.sanitize() before injecting as HTML, or render as text instead.',
  },
  {
    id: 'eval-user-input',
    name: 'eval / new Function with user input',
    severity: 'critical',
    re: /(?:^|[^.\w])(?:eval|Function|setTimeout|setInterval)\s*\(\s*[`'"][^`'"]*\$\{|(?:^|[^.\w])(?:eval|Function)\s*\(\s*(?:req\.|request\.|input|userInput|user_input|params\.|body\.|query\.)/,
    hint: 'eval()/new Function() on user input is RCE. Use JSON.parse, a parser library, or refactor to not need dynamic code.',
  },
  {
    id: 'jwt-no-verify',
    name: 'JWT decoded without signature verification',
    severity: 'high',
    re: /(?:jwt|jsonwebtoken)\s*\.\s*decode\s*\(/,
    hint: 'jwt.decode() does NOT verify the signature. Use jwt.verify(token, secret) — otherwise the token can be forged.',
  },
  {
    id: 'service-role-client',
    name: 'Supabase service-role key on the client',
    severity: 'critical',
    re: /createClient\s*\([^,]+,\s*[^,)]*(?:SERVICE_ROLE|service_role|SUPABASE_SERVICE)/i,
    hint: 'The service-role key bypasses RLS. Use it only in server-side code; for client use SUPABASE_ANON_KEY.',
  },
  {
    id: 'no-max-tokens',
    name: 'LLM call without max_tokens (cost runaway)',
    severity: 'high',
    re: /(?:anthropic|openai)\s*\.\s*(?:messages|chat\.completions|completions)\s*\.\s*create\s*\(\s*\{[^}]*model\s*:\s*['"`][^'"`]+['"`][^}]*\}\s*\)/m,
    requires: c => !/max_tokens\s*:/m.test(c),
    hint: 'LLM call has no max_tokens cap — one prompt-injection attack could cost thousands. Add e.g. `max_tokens: 1024`.',
  },
  {
    id: 'cors-wildcard-credentials',
    name: 'CORS wildcard with credentials',
    severity: 'critical',
    re: /Access-Control-Allow-Origin['"`]?\s*[:,]\s*['"`]\*['"`][\s\S]{0,200}Access-Control-Allow-Credentials['"`]?\s*[:,]\s*['"`]?true/i,
    hint: 'Wildcard origin + credentials is forbidden by spec and bypasses same-origin protections. Set Origin to a specific domain.',
  },
];

function scan(content, filePath) {
  const findings = [];
  for (const r of RULES) {
    if (r.requires && !r.requires(content)) continue;
    const m = r.re.exec(content);
    if (m) {
      // Find line number
      const before = content.slice(0, m.index);
      const line = before.split('\n').length;
      findings.push({ id: r.id, name: r.name, severity: r.severity, hint: r.hint, line, sample: m[0].slice(0, 120) });
    }
  }
  return findings;
}

function formatFindings(findings, filePath, mode) {
  const rel = path.relative(cwd, filePath);
  const headLine = mode === 'block'
    ? `🛑 agentic-security bodyguard: BLOCKED edit to ${rel}`
    : `⚠️  agentic-security bodyguard: ${findings.length} security risk(s) in proposed edit to ${rel}`;
  const lines = [headLine, ''];
  for (const f of findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.name}  (line ${f.line})`);
    lines.push(`     match: ${f.sample.replace(/\n/g, ' ')}`);
    lines.push(`     ${f.hint}`);
    lines.push('');
  }
  if (mode === 'block') {
    lines.push('Edit blocked. To override, either fix the issue, or change');
    lines.push('  .agentic-security/bodyguard.json  →  { "mode": "warn" }');
  } else {
    lines.push('(Edit allowed in warn mode. Set bodyguard.json mode="block" to enforce.)');
  }
  return lines.join('\n');
}

(async () => {
  const cfg = readCfg();
  if (cfg.mode === 'off') process.exit(0);

  const evt = await readStdinJSON();
  const tool = evt.tool_name || evt.toolName;
  if (!['Edit', 'Write', 'MultiEdit'].includes(tool)) process.exit(0);

  const input = evt.tool_input || {};
  const filePath = input.file_path || input.filePath || '';
  if (!filePath) process.exit(0);
  const rel = path.relative(cwd, filePath);
  if (rel.startsWith('..')) process.exit(0);

  for (const skip of (cfg.skipPaths || [])) {
    if (rel.includes(skip)) process.exit(0);
  }

  // Determine the proposed content depending on the tool variant
  let proposedContent = '';
  if (tool === 'Write') {
    proposedContent = input.content || '';
  } else if (tool === 'Edit') {
    proposedContent = input.new_string || '';
  } else if (tool === 'MultiEdit') {
    proposedContent = (input.edits || []).map(e => e.new_string || '').join('\n');
  }
  if (!proposedContent || proposedContent.length < 8) process.exit(0);

  const findings = scan(proposedContent, filePath);
  const crit = findings.filter(f => f.severity === 'critical');

  if (!findings.length) process.exit(0);

  const msg = formatFindings(findings, filePath, cfg.mode);

  if (cfg.mode === 'block' && crit.length > 0) {
    // Exit code 2 + stderr message is the PreToolUse "deny" signal in Claude Code
    process.stderr.write(msg + '\n');
    process.exit(2);
  } else {
    // Warn-only: stderr message visible to the user but edit proceeds
    process.stderr.write(msg + '\n');
    process.exit(0);
  }
})();
