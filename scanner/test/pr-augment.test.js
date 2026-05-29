// Tests for posture/pr-augment.js — PR-description auto-augmentation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

import { augmentPrBody, persistBaseline, loadBaseline, _internals } from '../src/posture/pr-augment.js';

async function mkProject() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'pra-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"pra-test"}');
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

async function writeScan(dir, findings) {
  await fsp.writeFile(
    path.join(dir, '.agentic-security', 'last-scan.json'),
    JSON.stringify({ findings, scannedAt: new Date().toISOString() }),
  );
}

const F = (overrides = {}) => ({
  id: 'F-' + Math.random().toString(36).slice(2),
  family: 'sqli', severity: 'high',
  file: 'src/routes/users.js', line: 10,
  vuln: 'SQL injection at users.js',
  attck: ['T1190'], attckName: 'Exploit Public-Facing Application',
  ...overrides,
});

test('pr-augment: returns ok=false when no last-scan present', async () => {
  const p = await mkProject();
  try {
    const r = augmentPrBody(p.dir);
    assert.equal(r.ok, false);
    assert.match(r.error, /no.*last-scan/i);
  } finally { await p.cleanup(); }
});

test('pr-augment: with no baseline, all findings count as added', async () => {
  const p = await mkProject();
  try {
    await writeScan(p.dir, [F({ severity: 'critical' }), F({ severity: 'high' })]);
    const r = augmentPrBody(p.dir, { baselineRef: 'main' });
    assert.equal(r.ok, true);
    assert.match(r.body, /Baseline against `main` not found/);
    assert.equal(r.summary.added, 2);
    assert.equal(r.summary.newCriticals, 1);
    assert.match(r.body, /Findings delta/);
  } finally { await p.cleanup(); }
});

test('pr-augment: persistBaseline + diff = correct added/removed', async () => {
  const p = await mkProject();
  try {
    const baseScan = { findings: [F({ id: 'A', file: 'src/a.js' }), F({ id: 'B', file: 'src/b.js' })] };
    persistBaseline(p.dir, 'main', baseScan);
    const reloaded = loadBaseline(p.dir, 'main');
    assert.ok(reloaded, 'baseline persisted');
    assert.equal(reloaded.findings.length, 2);

    // New scan removed B, added C
    await writeScan(p.dir, [F({ id: 'A', file: 'src/a.js' }), F({ id: 'C', file: 'src/c.js', severity: 'critical' })]);
    const r = augmentPrBody(p.dir, { baselineRef: 'main' });
    assert.equal(r.ok, true);
    assert.equal(r.summary.added, 1);
    assert.equal(r.summary.removed, 1);
    assert.equal(r.summary.newCriticals, 1);
    assert.match(r.body, /🛑.*critical/);
  } finally { await p.cleanup(); }
});

test('pr-augment: shows MITRE ATT&CK techniques in added findings', async () => {
  const p = await mkProject();
  try {
    await writeScan(p.dir, [
      F({ attck: ['T1190'], attckName: 'Exploit Public-Facing Application' }),
      F({ attck: ['T1059.007'], attckName: 'JavaScript Command and Scripting Interpreter' }),
    ]);
    const r = augmentPrBody(p.dir);
    assert.match(r.body, /T1190/);
    assert.match(r.body, /T1059\.007/);
  } finally { await p.cleanup(); }
});

test('pr-augment: suggests reviewer teams based on family', async () => {
  const p = await mkProject();
  try {
    await writeScan(p.dir, [
      F({ family: 'auth-missing' }),
      F({ family: 'pii-exposure', file: 'src/x.js' }),
      F({ family: 'iam-overpermissive', file: 'iam/y.json' }),
    ]);
    const r = augmentPrBody(p.dir);
    assert.equal(r.ok, true);
    const teams = r.summary.reviewers.map(x => x.team);
    assert.ok(teams.includes('security'));
    assert.ok(teams.includes('privacy'));
    assert.ok(teams.includes('platform'));
    assert.match(r.body, /Suggested reviewers/);
  } finally { await p.cleanup(); }
});

test('pr-augment: clean diff shows ✅ no new findings', async () => {
  const p = await mkProject();
  try {
    const findings = [F({ id: 'A' })];
    persistBaseline(p.dir, 'main', { findings });
    await writeScan(p.dir, findings);
    const r = augmentPrBody(p.dir, { baselineRef: 'main' });
    assert.equal(r.summary.added, 0);
    assert.match(r.body, /No new findings/);
  } finally { await p.cleanup(); }
});

test('pr-augment: blocking=false suppresses block-merge banner', async () => {
  const p = await mkProject();
  try {
    await writeScan(p.dir, [F({ severity: 'critical' })]);
    const r = augmentPrBody(p.dir, { blocking: false });
    assert.doesNotMatch(r.body, /🛑/);
  } finally { await p.cleanup(); }
});

test('pr-augment: artifact links surface when files exist', async () => {
  const p = await mkProject();
  try {
    await writeScan(p.dir, [F()]);
    await fsp.writeFile(path.join(p.dir, '.agentic-security', 'threat-model.md'), '# Threat model\n');
    await fsp.writeFile(path.join(p.dir, '.agentic-security', 'ATTRIBUTIONS.md'), '# Attributions\n');
    const r = augmentPrBody(p.dir);
    assert.match(r.body, /Threat model/);
    assert.match(r.body, /ATTRIBUTIONS/);
  } finally { await p.cleanup(); }
});

test('pr-augment: top 5 added findings rendered with file:line', async () => {
  const p = await mkProject();
  try {
    const findings = [];
    for (let i = 0; i < 8; i++) {
      findings.push(F({ id: `F-${i}`, file: `src/file-${i}.js`, line: 10 + i }));
    }
    await writeScan(p.dir, findings);
    const r = augmentPrBody(p.dir);
    assert.match(r.body, /Top added findings/);
    // First 5 file paths should appear
    for (let i = 0; i < 5; i++) {
      assert.match(r.body, new RegExp(`file-${i}\\.js`));
    }
  } finally { await p.cleanup(); }
});

test('pr-augment: internal helpers behave correctly', () => {
  const reviewers = _internals._suggestReviewers([
    { family: 'auth-missing' },
    { family: 'auth-missing' },
    { family: 'crypto-weak' },
    { family: 'unknown-family' },
  ]);
  // Both auth and crypto map to 'security' team
  const sec = reviewers.find(r => r.team === 'security');
  assert.ok(sec);
  assert.equal(sec.count, 3);
});
