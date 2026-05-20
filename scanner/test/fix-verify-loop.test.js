// v0.68 — closed-loop fix verification tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runProjectTests, verifyFixWithTests } from '../src/posture/fix-verify-loop.js';

function mkdir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `fvl-${name}-`));
}

test('runProjectTests: emits skipped+none when no runner is detected', () => {
  const dir = mkdir('none');
  const out = runProjectTests(dir);
  assert.equal(out.ok, true);
  assert.equal(out.runner, 'none');
  assert.equal(out.skipped, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: detects npm test from package.json', () => {
  const dir = mkdir('npm');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'demo', version: '1.0.0',
    scripts: { test: 'echo "skipping"; exit 0' },
  }));
  const out = runProjectTests(dir, { timeoutMs: 30_000 });
  assert.equal(out.runner, 'npm');
  // npm's exit may be non-zero on first-run if no node_modules; we accept
  // either result here. The shape of the response is what matters.
  assert.ok(typeof out.ok === 'boolean');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: respects runnerOverride for forced-deterministic tests', () => {
  const dir = mkdir('over');
  const out = runProjectTests(dir, {
    runnerOverride: { cmd: 'sh', args: ['-c', 'exit 0'] },
  });
  assert.equal(out.ok, true);
  assert.equal(out.runner, 'sh');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runProjectTests: failing runner emits ok=false', () => {
  const dir = mkdir('fail');
  const out = runProjectTests(dir, {
    runnerOverride: { cmd: 'sh', args: ['-c', 'exit 7'] },
  });
  assert.equal(out.ok, false);
  assert.equal(out.exitCode, 7);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: emits untested-but-passes when no runner exists', async () => {
  const dir = mkdir('utbp');
  // A trivial clean file — scan should be empty.
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
  });
  assert.equal(out.verdict, 'untested-but-passes');
  assert.equal(out.ok, true);
  assert.ok(out.summary.startsWith('untested-but-passes'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: verified-clean when overridden runner passes', async () => {
  const dir = mkdir('verok');
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
    testRunnerOverride: { cmd: 'sh', args: ['-c', 'exit 0'] },
  });
  assert.equal(out.verdict, 'verified-clean');
  assert.equal(out.ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('verifyFixWithTests: failing tests block verified-clean', async () => {
  const dir = mkdir('verfail');
  fs.writeFileSync(path.join(dir, 'safe.js'), 'export const x = 1;\n');
  const out = await verifyFixWithTests({
    scanRoot: dir,
    originalFindingStableId: 'nonexistent-stable-id',
    files: { 'safe.js': 'export const x = 1;\n' },
    testRunnerOverride: { cmd: 'sh', args: ['-c', 'exit 1'] },
  });
  assert.equal(out.verdict, 'verification-failed');
  assert.equal(out.ok, false);
  assert.equal(out.legs.tests.ok, false);
});
