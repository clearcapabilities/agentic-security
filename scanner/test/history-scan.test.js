// v0.68 — time-travel + counterfactual scan tests.
//
// The history mode requires a real git repo; we exercise it lightly. The
// what-if mode is pure file-overlay → scan delta, which we test fully.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runWhatIf } from '../src/history-scan.js';

function mkdir(name) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `wif-${name}-`));
}

test('runWhatIf: virtual overlay introduces a finding the baseline lacks', async () => {
  const dir = mkdir('intro');
  // Baseline file is clean.
  fs.writeFileSync(path.join(dir, 'app.js'), `
const express = require('express');
const app = express();
app.get('/u', (req, res) => res.json({ ok: 1 }));
`);
  // Overlay introduces an obvious eval-of-user-input vuln.
  const overlay = `
const express = require('express');
const app = express();
app.get('/u', (req, res) => {
  const code = req.query.code;
  eval(code);
  res.send('ran');
});
`;
  const r = await runWhatIf(dir, { overlays: [{ file: 'app.js', content: overlay }] });
  assert.ok(r.delta > 0, `expected delta > 0 from introducing eval; got ${r.delta}`);
  assert.ok(r.introduced.length > 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runWhatIf: virtually removing a vulnerable file removes its findings', async () => {
  const dir = mkdir('rm');
  // Baseline includes a vulnerable file.
  fs.writeFileSync(path.join(dir, 'app.js'), `
const { exec } = require('child_process');
exec('rm -rf ' + process.argv[2]);
`);
  fs.writeFileSync(path.join(dir, 'safe.js'), `export const x = 1;\n`);
  const r = await runWhatIf(dir, { remove: ['app.js'] });
  assert.ok(r.delta <= 0,
    `removing the vulnerable file should not introduce findings; delta=${r.delta}`);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runWhatIf: identity overlay (same content) produces zero delta', async () => {
  const dir = mkdir('id');
  const code = `
const express = require('express');
const app = express();
app.get('/u', (req, res) => res.send('hi'));
`;
  fs.writeFileSync(path.join(dir, 'app.js'), code);
  const r = await runWhatIf(dir, { overlays: [{ file: 'app.js', content: code }] });
  assert.equal(r.delta, 0,
    `identity overlay should produce zero delta; got ${r.delta}`);
  assert.equal(r.introduced.length, 0);
  assert.equal(r.removed.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runWhatIf: adding a brand-new file via overlay is detected', async () => {
  const dir = mkdir('newfile');
  fs.writeFileSync(path.join(dir, 'existing.js'), `export const x = 1;\n`);
  const overlay = `
const { exec } = require('child_process');
const express = require('express');
const app = express();
app.get('/r', (req, res) => exec(req.query.cmd));
`;
  const r = await runWhatIf(dir, { overlays: [{ file: 'new.js', content: overlay }] });
  assert.ok(r.delta > 0,
    `adding a vulnerable file should raise findings; delta=${r.delta}`);
  fs.rmSync(dir, { recursive: true, force: true });
});
