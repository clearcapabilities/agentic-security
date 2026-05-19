#!/usr/bin/env node
// SessionStart hook: validate that this plugin's own surfaces (commands,
// agents, hooks) have well-formed frontmatter and required fields. The
// failure mode this prevents: a malformed markdown file in commands/ or
// agents/ gets silently skipped by Claude Code at load time. The user
// never knows their `/foo` command isn't actually registered.
//
// Harness-engineering note: hard-rejection on malformed surfaces, surfaced
// to stderr (which Claude Code shows). Does NOT block the session — the
// SessionStart hook exits 0 either way — but the operator/agent sees the
// warning and can fix it.
//
// Runs only against the plugin root (the directory that owns this hook),
// NOT against the user's project. So a malformed commands/foo.md in the
// plugin trips the check; a markdown file in the user's project does not.
'use strict';
const fs = require('fs');
const path = require('path');

const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, '..');

function readStdinJSON() {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve({});
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', c => { data += c; });
    process.stdin.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    setTimeout(() => resolve({}), 800);
  });
}

function parseFrontmatter(body) {
  // Minimal YAML frontmatter parser — `--- key: value\n ... ---` at top.
  // We only need to know whether the block exists and what top-level scalar
  // keys are present.
  if (!body.startsWith('---\n')) return { ok: false, reason: 'missing-frontmatter-fence' };
  const close = body.indexOf('\n---', 4);
  if (close < 0) return { ok: false, reason: 'unterminated-frontmatter' };
  const block = body.slice(4, close);
  const keys = {};
  for (const rawLine of block.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([a-zA-Z_][\w-]*)\s*:\s*(.*)$/.exec(line);
    if (m) keys[m[1]] = m[2];
  }
  return { ok: true, keys };
}

function _walkMarkdown(dir) {
  if (!fs.existsSync(dir)) return [];
  try {
    return fs.readdirSync(dir)
      .filter(n => n.endsWith('.md') && !n.startsWith('_') && !n.startsWith('.'))
      .map(n => path.join(dir, n));
  } catch { return []; }
}

const issues = [];

function checkCommand(fp) {
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); }
  catch (e) { issues.push({ file: fp, kind: 'command', reason: `unreadable: ${e.message}` }); return; }
  const fm = parseFrontmatter(body);
  if (!fm.ok) { issues.push({ file: fp, kind: 'command', reason: fm.reason }); return; }
  if (!fm.keys.description) issues.push({ file: fp, kind: 'command', reason: 'missing-description-in-frontmatter' });
}

function checkAgent(fp) {
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); }
  catch (e) { issues.push({ file: fp, kind: 'agent', reason: `unreadable: ${e.message}` }); return; }
  const fm = parseFrontmatter(body);
  if (!fm.ok) { issues.push({ file: fp, kind: 'agent', reason: fm.reason }); return; }
  if (!fm.keys.name) issues.push({ file: fp, kind: 'agent', reason: 'missing-name-in-frontmatter' });
  if (!fm.keys.description) issues.push({ file: fp, kind: 'agent', reason: 'missing-description-in-frontmatter' });
  if (!fm.keys.tools) issues.push({ file: fp, kind: 'agent', reason: 'missing-tools-in-frontmatter' });
}

function checkHook(fp) {
  if (!fs.existsSync(fp)) {
    issues.push({ file: fp, kind: 'hook', reason: 'missing' });
    return;
  }
  // Sanity: file is non-empty and starts with a shebang OR a node-style guard.
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); }
  catch (e) { issues.push({ file: fp, kind: 'hook', reason: `unreadable: ${e.message}` }); return; }
  if (body.length < 20) issues.push({ file: fp, kind: 'hook', reason: 'suspiciously-short' });
}

(async () => {
  await readStdinJSON(); // drain stdin so the parent doesn't hang
  // Commands.
  for (const fp of _walkMarkdown(path.join(pluginRoot, 'commands'))) checkCommand(fp);
  // Agents.
  for (const fp of _walkMarkdown(path.join(pluginRoot, 'agents'))) checkAgent(fp);
  // Hooks declared in hooks.json must exist on disk.
  const hooksJsonPath = path.join(pluginRoot, 'hooks', 'hooks.json');
  if (fs.existsSync(hooksJsonPath)) {
    let cfg;
    try { cfg = JSON.parse(fs.readFileSync(hooksJsonPath, 'utf8')); }
    catch (e) { issues.push({ file: hooksJsonPath, kind: 'hooks-json', reason: `parse-failed: ${e.message}` }); cfg = null; }
    if (cfg && cfg.hooks && typeof cfg.hooks === 'object') {
      for (const eventName of Object.keys(cfg.hooks)) {
        const arr = Array.isArray(cfg.hooks[eventName]) ? cfg.hooks[eventName] : [];
        for (const entry of arr) {
          const hooksList = Array.isArray(entry.hooks) ? entry.hooks : [];
          for (const h of hooksList) {
            const cmd = String(h.command || '');
            const m = /\${CLAUDE_PLUGIN_ROOT}\/(\S+)/.exec(cmd);
            if (!m) continue;
            const rel = m[1].split(/\s+/)[0]; // strip args
            checkHook(path.join(pluginRoot, rel));
          }
        }
      }
    }
  }

  if (issues.length) {
    process.stderr.write(`agentic-security: plugin self-check found ${issues.length} issue(s):\n`);
    for (const i of issues.slice(0, 20)) {
      const rel = path.relative(pluginRoot, i.file);
      process.stderr.write(`  · [${i.kind}] ${rel} — ${i.reason}\n`);
    }
    if (issues.length > 20) process.stderr.write(`  · …and ${issues.length - 20} more\n`);
    process.stderr.write(`  (SessionStart warning only; session continues. Fix to unbreak the affected surface.)\n`);
  }
  process.exit(0);
})();
