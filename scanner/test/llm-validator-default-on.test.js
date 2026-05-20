// v0.66 — LLM validator default-on tests.
//
// Verifies the opt-in → opt-out flip:
//   - No endpoint configured + no env vars → no-op, findings annotated as unvalidated.
//   - Endpoint configured + no env vars → validator RUNS (default-on).
//   - Endpoint configured + VALIDATE=0  → no-op (opt-out).
//   - Endpoint configured + VALIDATE=1  → validator RUNS (legacy opt-in still works).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { validateMany } from '../src/llm-validator/index.js';

function makeFindings() {
  return [{
    id: 'test-1', stableId: 'test-1',
    file: 'a.js', line: 10,
    severity: 'high', confidence: 0.9, parser: 'AST',
    vuln: 'SQL Injection', cwe: 'CWE-89',
  }];
}

function withEnv(overrides, body) {
  const snapshot = {};
  for (const k of Object.keys(overrides)) snapshot[k] = process.env[k];
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try { return body(); }
  finally {
    for (const [k, v] of Object.entries(snapshot)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('no endpoint configured: no-op, findings unvalidated, no network attempt', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: undefined,
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = makeFindings();
    let fetchCalled = false;
    const origFetch = global.fetch;
    global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
    try {
      await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    } finally { global.fetch = origFetch; }
    assert.equal(fetchCalled, false, 'no fetch should be attempted without an endpoint');
    assert.equal(findings[0].validator_verdict, 'unvalidated');
    assert.equal(findings[0].unvalidated, true);
  });
});

test('endpoint configured + no env vars: validator RUNS (default-on)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-defon-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const findings = makeFindings();
    let fetchCalled = 0;
    const origFetch = global.fetch;
    // Simulate an endpoint that returns a properly-shaped, accepting verdict.
    global.fetch = async (url, opts) => {
      fetchCalled++;
      const body = JSON.parse(opts.body);
      // Echo back the challenge embedded in the prompt.
      const m = body.prompt.match(/"challenge": "([a-f0-9]+)"/);
      const challenge = m ? m[1] : '00000000';
      const fm = body.prompt.match(/"file": "([^"]+)"/);
      const file = fm ? fm[1] : '';
      const lm = body.prompt.match(/"line": (\d+)/);
      const line = lm ? Number(lm[1]) : 0;
      const obj = { challenge, file, line, verdict: 'accept', confidence: 0.85, reasoning: 'looks real' };
      return { ok: true, json: async () => ({ response: 'final answer:\n' + JSON.stringify(obj) }) };
    };
    try {
      await validateMany(findings, { fileContents: { 'a.js': 'line1\n'.repeat(20) }, scanRoot: dir });
    } finally { global.fetch = origFetch; }
    assert.ok(fetchCalled >= 1, 'default-on: fetch should be called');
    assert.equal(findings[0].validator_verdict, 'accept');
    assert.equal(findings[0].unvalidated, undefined);
  });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('endpoint configured + VALIDATE=0: explicit opt-out, no fetch', async () => {
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_VALIDATE: '0',
  }, async () => {
    const findings = makeFindings();
    let fetchCalled = false;
    const origFetch = global.fetch;
    global.fetch = async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; };
    try {
      await validateMany(findings, { fileContents: {}, scanRoot: os.tmpdir() });
    } finally { global.fetch = origFetch; }
    assert.equal(fetchCalled, false, 'VALIDATE=0 must suppress all fetches');
    assert.equal(findings[0].validator_verdict, 'unvalidated');
  });
});

test('cache hit on second run: no network call', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v-cache-'));
  await withEnv({
    AGENTIC_SECURITY_LLM_ENDPOINT: 'http://localhost:0/never',
    AGENTIC_SECURITY_LLM_API_KEY: 'fake',
    AGENTIC_SECURITY_LLM_MODEL: 'test-model',
    AGENTIC_SECURITY_LLM_VALIDATE: undefined,
  }, async () => {
    const fileContents = { 'a.js': 'line1\n'.repeat(20) };
    let fetchCalled = 0;
    const origFetch = global.fetch;
    global.fetch = async (url, opts) => {
      fetchCalled++;
      const body = JSON.parse(opts.body);
      const m = body.prompt.match(/"challenge": "([a-f0-9]+)"/);
      const challenge = m ? m[1] : '00000000';
      const fm = body.prompt.match(/"file": "([^"]+)"/);
      const file = fm ? fm[1] : '';
      const lm = body.prompt.match(/"line": (\d+)/);
      const line = lm ? Number(lm[1]) : 0;
      return { ok: true, json: async () => ({ response: JSON.stringify({ challenge, file, line, verdict: 'reject', confidence: 0.9, reasoning: 'sanitized upstream' }) }) };
    };
    try {
      await validateMany(makeFindings(), { fileContents, scanRoot: dir });
      const before = fetchCalled;
      await validateMany(makeFindings(), { fileContents, scanRoot: dir });
      assert.equal(fetchCalled, before,
        `cache should suppress the second network call (was ${before}, became ${fetchCalled})`);
    } finally { global.fetch = origFetch; }
  });
  fs.rmSync(dir, { recursive: true, force: true });
});
