import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanStoredTaint } from '../src/sast/stored-taint.js';

const VULN = "const row = await db.query('SELECT * FROM u');\nres.send(row.bio);\n";

test('is OFF by default (opt-in only) — no findings without the flag', () => {
  delete process.env.AGENTIC_SECURITY_STORED_TAINT;
  assert.equal(scanStoredTaint('a.js', VULN).length, 0);
});

test('when enabled, flags a store-read value reaching a sink', () => {
  process.env.AGENTIC_SECURITY_STORED_TAINT = '1';
  try {
    const f = scanStoredTaint('a.js', VULN);
    assert.ok(f.length >= 1);
    assert.equal(f[0].family, 'xss');
    assert.ok(f[0].confidence <= 0.5, 'stored taint is lower-confidence by design');
  } finally {
    delete process.env.AGENTIC_SECURITY_STORED_TAINT;
  }
});

test('when enabled, does NOT flag when the read value is re-validated', () => {
  process.env.AGENTIC_SECURITY_STORED_TAINT = '1';
  try {
    const safe = "const row = await db.query('SELECT 1');\nconst clean = escape(row.bio);\nres.send(clean);\n";
    assert.equal(scanStoredTaint('a.js', safe).length, 0);
  } finally {
    delete process.env.AGENTIC_SECURITY_STORED_TAINT;
  }
});

test('ignores unrelated files even when enabled', () => {
  process.env.AGENTIC_SECURITY_STORED_TAINT = '1';
  try {
    assert.equal(scanStoredTaint('a.txt', VULN).length, 0);
  } finally {
    delete process.env.AGENTIC_SECURITY_STORED_TAINT;
  }
});
