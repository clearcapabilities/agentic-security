// Tests for hooks/pre-edit-bodyguard.js — PreToolUse vulnerability prevention.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(__dirname, '..', '..', 'hooks', 'pre-edit-bodyguard.js');

async function mkProject({ mode, bans } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-bg-'));
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"bg-test"}');
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  if (mode) {
    await fsp.writeFile(path.join(stateDir, 'bodyguard.json'), JSON.stringify({ mode }));
  }
  if (bans) {
    await fsp.writeFile(path.join(stateDir, 'forbidden-apis.json'), JSON.stringify({ bans }));
  }
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

function runBodyguard(projectDir, evt) {
  return new Promise((resolve) => {
    const child = cp.spawn('node', [BIN], {
      env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('exit', (code) => resolve({ code, stderr }));
    child.stdin.write(JSON.stringify(evt));
    child.stdin.end();
  });
}

test('bodyguard: critical SQL injection blocks in block mode', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
      },
    });
    assert.equal(r.code, 2, 'block mode + critical → exit 2');
    assert.match(r.stderr, /BLOCKED/);
    assert.match(r.stderr, /SQL injection/);
  } finally { await p.cleanup(); }
});

test('bodyguard: critical SQL injection warns in warn mode (default)', async () => {
  const p = await mkProject();
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
      },
    });
    assert.equal(r.code, 0, 'warn mode → exit 0 (edit proceeds)');
    assert.match(r.stderr, /security risk/);
  } finally { await p.cleanup(); }
});

test('bodyguard: clean content exits silently', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'function add(a, b) { return a + b; }',
      },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stderr, '');
  } finally { await p.cleanup(); }
});

test('bodyguard: off mode skips entirely', async () => {
  const p = await mkProject({ mode: 'off' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
      },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stderr, '');
  } finally { await p.cleanup(); }
});

test('bodyguard: skipPaths excludes test/ fixtures/', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'test', 'fixtures', 'vuln.js'),
        content: 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)',
      },
    });
    assert.equal(r.code, 0, 'fixtures path skipped');
  } finally { await p.cleanup(); }
});

test('bodyguard: pickle.load on request input flagged critical', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.py'),
        content: 'import pickle\ndata = pickle.loads(request.data)',
      },
    });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /pickle/i);
  } finally { await p.cleanup(); }
});

test('bodyguard: rejectUnauthorized: false flagged critical', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'fetch.js'),
        content: 'const agent = new https.Agent({ rejectUnauthorized: false });',
      },
    });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /TLS/);
  } finally { await p.cleanup(); }
});

test('bodyguard: SSRF to 169.254.169.254 blocked', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'meta.js'),
        content: 'fetch(`http://169.254.169.254/latest/meta-data/iam/security-credentials/`)',
      },
    });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /metadata/i);
  } finally { await p.cleanup(); }
});

test('bodyguard: JWT alg=none blocked', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'auth.js'),
        content: 'jwt.verify(token, key, { algorithms: ["none"] })',
      },
    });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /alg/);
  } finally { await p.cleanup(); }
});

test('bodyguard: forbidden-APIs.json blocks per-project ban', async () => {
  const p = await mkProject({
    mode: 'block',
    bans: [{ pattern: '\\blegacyDb\\b', message: 'legacyDb is deprecated; use db.* instead' }],
  });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'const users = await legacyDb.fetch();',
      },
    });
    assert.equal(r.code, 2, 'project-banned API → blocked');
    assert.match(r.stderr, /Forbidden API/);
    assert.match(r.stderr, /legacyDb is deprecated/);
  } finally { await p.cleanup(); }
});

test('bodyguard: malformed forbidden-APIs regex does not crash', async () => {
  const p = await mkProject({
    mode: 'block',
    bans: [{ pattern: '[invalid', message: 'bad regex' }],
  });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'Write',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        content: 'function add(a, b) { return a + b; }',
      },
    });
    assert.equal(r.code, 0, 'clean content passes even with bad regex in config');
  } finally { await p.cleanup(); }
});

test('bodyguard: MultiEdit scans concatenated edits', async () => {
  const p = await mkProject({ mode: 'block' });
  try {
    const r = await runBodyguard(p.dir, {
      tool_name: 'MultiEdit',
      tool_input: {
        file_path: path.join(p.dir, 'app.js'),
        edits: [
          { old_string: 'foo', new_string: 'bar' },
          { old_string: 'baz', new_string: 'db.query(`SELECT * FROM x WHERE id = ${req.body.id}`)' },
        ],
      },
    });
    assert.equal(r.code, 2);
    assert.match(r.stderr, /SQL injection/);
  } finally { await p.cleanup(); }
});
