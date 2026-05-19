// Transcript-review CLI tests (eval-post recommendation #6).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { auditCall } from '../src/mcp/audit.js';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const BIN = path.resolve(__dirname, '..', 'bin', 'agentic-security-audit.js');

function mkLog(entries) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-cli-'));
  for (const e of entries) auditCall({ sessionRoot: root, ...e });
  return root;
}

function run(args, root) {
  return cp.spawnSync('node', [BIN, ...args, '--root', root], { encoding: 'utf8', timeout: 4000 });
}

test('review prints filtered entries', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: { files: ['a.js'] }, outcome: 'ok' },
    { tool: 'apply_fix', args: { finding_id: 'f1' }, outcome: 'rejected', reason: 'no-confirm' },
    { tool: 'apply_fix', args: { finding_id: 'f2', confirm: true }, outcome: 'ok' },
  ]);
  const r = run(['review', '--last', '1h', '--n', '10'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /scan_diff/);
  assert.match(r.stdout, /apply_fix/);
  assert.match(r.stdout, /\[REJ\]/);
});

test('review filters by tool', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: { files: ['a.js'] }, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  const r = run(['review', '--tool', 'apply_fix', '--last', '1h'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /apply_fix/);
  assert.ok(!/scan_diff/.test(r.stdout));
});

test('review filters by outcome', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'rejected', reason: 'r' },
  ]);
  const r = run(['review', '--outcome', 'rejected', '--last', '1h'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /apply_fix/);
  assert.ok(!/\[ OK\].*scan_diff/.test(r.stdout));
});

test('metrics aggregates by tool', () => {
  const root = mkLog([
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'rejected', reason: 'r' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
  ]);
  const r = run(['metrics', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.byTool.apply_fix.total, 3);
  assert.equal(out.byTool.apply_fix.ok, 2);
  assert.equal(out.byTool.apply_fix.rejected, 1);
});

test('verify reports OK on a clean chain', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  const r = run(['verify'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Audit chain verified: 2 entries/);
});

test('verify fails on tampered chain', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
  ]);
  // Tamper: rewrite the second line's prev hash to a wrong value.
  const fp = path.join(root, '.agentic-security', 'mcp-audit.log');
  const lines = fs.readFileSync(fp, 'utf8').split('\n').filter(Boolean);
  const e1 = JSON.parse(lines[1]);
  e1.prev = '0000000000000000000000000000000000000000000000000000000000000000';
  lines[1] = JSON.stringify(e1);
  fs.writeFileSync(fp, lines.join('\n') + '\n');
  const r = run(['verify'], root);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Audit chain BROKEN/);
});

test('review on empty log prints "No entries match"', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-empty-'));
  const r = run(['review'], root);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No entries match/);
});

// ─── harness-anatomy #9: by-session metrics ─────────────────────────────────

test('metrics --by-session groups entries with the same sessionId', () => {
  const root = mkLog([
    { tool: 'scan_diff', args: {}, outcome: 'ok' },
    { tool: 'apply_fix', args: {}, outcome: 'ok' },
    { tool: 'query_taint', args: {}, outcome: 'ok' },
  ]);
  const r = run(['metrics', '--by-session', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  // All entries share the same in-process sessionId.
  assert.equal(out.totalSessions, 1);
  assert.equal(out.sessions[0].total, 3);
});

test('metrics --by-session flags outliers above threshold', () => {
  // 25 calls of the same tool in the same session → outlier at threshold=10.
  const entries = [];
  for (let i = 0; i < 25; i++) entries.push({ tool: 'apply_fix', args: {}, outcome: 'ok' });
  const root = mkLog(entries);
  const r = run(['metrics', '--by-session', '--outlier-threshold', '10', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.sessions[0].outlier, true);
  assert.equal(out.sessions[0].maxToolCount, 25);
});

test('metrics --by-session handles legacy entries without sessionId', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-legacy-'));
  const stateDir = path.join(root, '.agentic-security');
  fs.mkdirSync(stateDir, { recursive: true });
  // Hand-craft a pre-instrumentation entry (no sessionId field). The bucket
  // should be labelled "pre-instrumented" so legacy logs still aggregate.
  const entry = { ts: new Date().toISOString(), tool: 'scan_diff', outcome: 'ok', args: '{}', prev: 'GENESIS' };
  fs.writeFileSync(path.join(stateDir, 'mcp-audit.log'), JSON.stringify(entry) + '\n');
  const r = run(['metrics', '--by-session', '--last', '1h', '--json'], root);
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.sessions[0].sessionId, 'pre-instrumented');
});
