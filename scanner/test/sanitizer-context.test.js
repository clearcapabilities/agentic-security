// R5 — context-aware sanitizer adequacy (wrong sanitizer for the sink context).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSanitizerContextMismatch } from '../src/sast/wrong-context-sanitizer.js';

test('HTML-escape before a shell sink → command-injection wrong-context (CWE-78)', () => {
  const f = scanSanitizerContextMismatch('a.js', `exec('ping ' + escapeHtml(req.query.host));`);
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-78');
  assert.equal(f[0].family, 'command-injection');
});

test('HTML-escape before a SQL sink → sql-injection wrong-context (CWE-89)', () => {
  const f = scanSanitizerContextMismatch('a.js', `db.query("SELECT * FROM u WHERE n = '" + htmlspecialchars(name) + "'");`);
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-89');
});

test('one assignment hop: const safe = escapeHtml(h); execSync(safe) fires', () => {
  const f = scanSanitizerContextMismatch('a.js', `const safe = escapeHtml(h);\nexecSync(safe);`);
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-78');
});

test('precision: HTML-escape for actual HTML output does not fire', () => {
  assert.equal(scanSanitizerContextMismatch('a.js', `res.send('<b>' + escapeHtml(name) + '</b>');`).length, 0);
});

test('precision: argv-form execFile with no HTML encoder does not fire', () => {
  assert.equal(scanSanitizerContextMismatch('a.js', `execFile('ping', ['-c', '1', host]);`).length, 0);
});

test('precision: HTML encoder present but no shell/sql sink does not fire', () => {
  assert.equal(scanSanitizerContextMismatch('a.js', `const x = escapeHtml(name); el.textContent = x;`).length, 0);
});
