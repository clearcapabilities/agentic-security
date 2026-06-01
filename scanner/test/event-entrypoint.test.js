// R6 — non-HTTP entrypoint taint tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanEventEntrypoints } from '../src/sast/event-entrypoint.js';

test('JS serverless handler: event payload → exec fires', () => {
  const code = `
    const { exec } = require('child_process');
    exports.handler = async (event) => {
      exec('process ' + event.body);
    };
  `;
  const f = scanEventEntrypoints('h.js', code);
  assert.equal(f.length, 1);
  assert.equal(f[0].family, 'command-injection');
});

test('Python Celery task: arg → os.system fires', () => {
  const code = [
    'import os',
    '@app.task',
    'def run_job(arg):',
    '    os.system(arg)',
  ].join('\n');
  const f = scanEventEntrypoints('t.py', code);
  assert.ok(f.length >= 1);
  assert.equal(f[0].cwe, 'CWE-78');
});

test('JS queue consumer: msg → eval fires', () => {
  const code = `
    kafkaConsumer.on('message', (msg) => {
      eval(msg.value);
    });
  `;
  assert.equal(scanEventEntrypoints('c.js', code).length, 1);
});

test('precision: validated payload (schema.parse) suppresses', () => {
  const code = `
    exports.handler = async (event) => {
      const clean = schema.parse(event.body);
      exec(clean);
    };
  `;
  assert.equal(scanEventEntrypoints('h.js', code).length, 0);
});

test('precision: non-event file (no entrypoint context) does not fire', () => {
  const code = `function f(x){ exec(x); }`;
  assert.equal(scanEventEntrypoints('a.js', code).length, 0);
});

test('precision: entrypoint without a dangerous sink does not fire', () => {
  const code = `
    exports.handler = async (event) => { return { ok: event.body }; };
  `;
  assert.equal(scanEventEntrypoints('h.js', code).length, 0);
});
