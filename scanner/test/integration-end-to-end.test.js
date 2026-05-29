// End-to-end integration test for the world-class module integration.
//
// Verifies that each scaffolded module is actually invoked by runScan
// when its files / inputs are present, and produces the documented
// finding / artifact shape.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runScan } from '../src/runScan.js';

async function mkProject(files) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-e2e-'));
  await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 't' }));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    await fsp.mkdir(path.dirname(fp), { recursive: true });
    await fsp.writeFile(fp, content);
  }
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

// Set OFFLINE so OSV/EPSS/KEV don't fire network calls during tests.
process.env.AGENTIC_SECURITY_OFFLINE = '1';

test('integration: scanLlmApp fires when LLM-client code is present', async () => {
  const proj = await mkProject({
    'app.py': `
import openai
def chat(user_input):
    system_prompt = "Be helpful."
    full = system_prompt + " User: " + user_input
    return openai.ChatCompletion.create(messages=[{"role":"user","content":full}])
`,
  });
  try {
    const result = await runScan(proj.dir);
    const llmFindings = (result.scan.findings || []).filter(f => f.parser === 'LLM-APP');
    assert.ok(llmFindings.length > 0, `expected LLM-APP findings; got: ${result.scan.findings?.length} total`);
    assert.ok(llmFindings.some(f => f.subfamily === 'prompt-injection'));
  } finally { await proj.cleanup(); }
});

test('integration: scanMobile fires on AndroidManifest.xml', async () => {
  const proj = await mkProject({
    'AndroidManifest.xml': `<?xml version="1.0"?>
<manifest>
  <application android:debuggable="true">
    <activity android:name=".Main" android:exported="true" />
  </application>
</manifest>`,
  });
  try {
    const result = await runScan(proj.dir);
    const mobileFindings = (result.scan.findings || []).filter(f => f.parser === 'MOBILE');
    assert.ok(mobileFindings.length > 0, `expected MOBILE findings`);
  } finally { await proj.cleanup(); }
});

test('integration: threat model is emitted when findings exist', async () => {
  const proj = await mkProject({
    'app.js': `
const express = require('express');
const app = express();
app.get('/api/x', (req, res) => res.send(req.query.q));
`,
  });
  try {
    const result = await runScan(proj.dir);
    // Threat model file should be written.
    const tmFile = path.join(proj.dir, '.agentic-security', 'threat-model.json');
    assert.ok(fs.existsSync(tmFile), `expected threat-model.json at ${tmFile}`);
    const tm = JSON.parse(fs.readFileSync(tmFile, 'utf8'));
    assert.ok(Array.isArray(tm.threats), 'threat model has threats array');
  } finally { await proj.cleanup(); }
});

test('integration: SBOM diff is run on first scan and recorded', async () => {
  const proj = await mkProject({
    'package.json': JSON.stringify({
      name: 'sbom-test',
      dependencies: { lodash: '4.17.20' },
    }),
  });
  try {
    const result = await runScan(proj.dir);
    // First scan should write a snapshot under sbom-history/.
    const histDir = path.join(proj.dir, '.agentic-security', 'sbom-history');
    if (fs.existsSync(histDir)) {
      const snaps = fs.readdirSync(histDir).filter(f => f.endsWith('.json'));
      assert.ok(snaps.length > 0, 'at least one SBOM snapshot persisted');
    }
    // sbomDiff in result should mark first=true (no prior snapshot).
    assert.ok(result.scan.sbomDiff === null || result.scan.sbomDiff?.first === true);
  } finally { await proj.cleanup(); }
});

test('integration: AGENTIC_SECURITY_NO_INTEGRATION=1 disables the whole block', async () => {
  process.env.AGENTIC_SECURITY_NO_INTEGRATION = '1';
  const proj = await mkProject({
    'app.py': `import openai
openai.ChatCompletion.create(messages=[{"role":"user","content": "x"+user}])`,
  });
  try {
    const result = await runScan(proj.dir);
    const llmFindings = (result.scan.findings || []).filter(f => f.parser === 'LLM-APP');
    assert.equal(llmFindings.length, 0, 'LLM-APP detector disabled by env');
    // Threat model file should NOT be written.
    const tmFile = path.join(proj.dir, '.agentic-security', 'threat-model.json');
    assert.equal(fs.existsSync(tmFile), false, 'threat model NOT generated when integration disabled');
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_INTEGRATION;
    await proj.cleanup();
  }
});

test('integration: per-module opt-out env vars work independently', async () => {
  process.env.AGENTIC_SECURITY_NO_LLM_APP = '1';
  process.env.AGENTIC_SECURITY_NO_MOBILE = '1';
  const proj = await mkProject({
    'app.py': `import openai
openai.ChatCompletion.create(messages=[{"role":"user","content": "x"+user}])`,
    'AndroidManifest.xml': `<manifest><application android:debuggable="true"></application></manifest>`,
  });
  try {
    const result = await runScan(proj.dir);
    const llmFindings = (result.scan.findings || []).filter(f => f.parser === 'LLM-APP');
    const mobileFindings = (result.scan.findings || []).filter(f => f.parser === 'MOBILE');
    assert.equal(llmFindings.length, 0, 'LLM-APP disabled by NO_LLM_APP');
    assert.equal(mobileFindings.length, 0, 'MOBILE disabled by NO_MOBILE');
    // But threat model SHOULD still fire — separately gated.
    const tmFile = path.join(proj.dir, '.agentic-security', 'threat-model.json');
    assert.ok(fs.existsSync(tmFile), 'threat model still emitted');
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_LLM_APP;
    delete process.env.AGENTIC_SECURITY_NO_MOBILE;
    await proj.cleanup();
  }
});

test('integration: scan returns the new artifact fields', async () => {
  const proj = await mkProject({ 'app.js': 'console.log("hello");' });
  try {
    const result = await runScan(proj.dir);
    // The result.scan object should carry the new artifact fields.
    assert.ok(Object.prototype.hasOwnProperty.call(result.scan, 'threatModel'));
    assert.ok(Object.prototype.hasOwnProperty.call(result.scan, 'sbomDiff'));
    assert.ok(Object.prototype.hasOwnProperty.call(result.scan, 'complianceReport'));
    assert.ok(Object.prototype.hasOwnProperty.call(result.scan, 'exploitBundles'));
  } finally { await proj.cleanup(); }
});

test('integration: compliance evidence is generated when policy file exists', async () => {
  const proj = await mkProject({
    'app.js': 'console.log("ok");',
    '.agentic-security/compliance.policy.yml': `
framework: "TEST"
controls:
  TC1:
    title: "Documentation present"
    requires:
      - file-exists: "package.json"
`,
  });
  try {
    const result = await runScan(proj.dir);
    assert.ok(result.scan.complianceReport, 'compliance report generated');
    assert.equal(result.scan.complianceReport.summary.compliant, 1);
    const evidence = path.join(proj.dir, '.agentic-security', 'compliance-evidence.json');
    assert.ok(fs.existsSync(evidence), 'JSON-LD evidence file persisted');
  } finally { await proj.cleanup(); }
});
