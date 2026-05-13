---
description: Generate failing security tests for each finding and passing tests that prove fixes work — in your project's test framework.
argument-hint: "[--finding <id>] | [--all] | [--critical]"
---

Generate security regression tests — code you commit to the test suite that proves a vulnerability exists (failing) and proves your fix works (passing).

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const arg = process.argv[1] || '--critical';
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first.');
  process.exit(0);
}

// Detect test framework
const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const deps = pkg ? { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) } : {};
const hasVitest = Object.keys(deps).some(k => k === 'vitest');
const hasJest = Object.keys(deps).some(k => k === 'jest' || k === '@jest/core');
const hasPytest = fs.existsSync('pytest.ini') || fs.existsSync('pyproject.toml');
const framework = hasVitest ? 'vitest' : hasJest ? 'jest' : hasPytest ? 'pytest' : 'node:test';

// Filter findings to test-generate
let targets = scan.findings || [];
if (arg === '--critical') targets = targets.filter(f => f.severity === 'critical' || f.severity === 'high');
else if (arg.startsWith('--finding ')) {
  const id = arg.replace('--finding ', '').trim();
  targets = targets.filter(f => f.id === id);
}
targets = targets.slice(0, 10); // cap at 10 to keep output manageable

console.log('');
console.log(W('Security Regression Test Generator', '1'));
console.log('  Framework: ' + framework);
console.log('  Findings to cover: ' + targets.length);
console.log('');

// Output finding summaries for Claude to generate tests
console.log(JSON.stringify({
  framework,
  appType: Object.keys(deps).some(k=>k==='next') ? 'nextjs' : Object.keys(deps).some(k=>k==='express') ? 'express' : 'node',
  testDir: fs.existsSync('src/__tests__') ? 'src/__tests__' : fs.existsSync('test') ? 'test' : fs.existsSync('tests') ? 'tests' : '__tests__',
  findings: targets.map(f => ({
    id: f.id,
    vuln: f.vuln,
    severity: f.severity,
    file: f.file,
    line: f.line,
    description: f.description,
    cwe: f.cwe,
  })),
}, null, 2));
" -- "$1"
```

Using the JSON above, generate a test file for each finding. For each finding write:

**Test structure per finding:**
```
describe('<vuln name>', () => {
  test('VULNERABILITY: <what the attacker does>', async () => {
    // Set up the vulnerable state (call the actual function/endpoint)
    // Assert the vulnerability IS exploitable (this test should FAIL after the fix)
    // e.g., expect(response.status).not.toBe(403) when it should be 403
  });

  test('FIXED: <what the fix prevents>', async () => {
    // Same setup but with the fix applied
    // Assert the vulnerability is NOT exploitable
    // e.g., expect(sanitized).not.toContain('<script>')
  });
});
```

Rules:
- Use the detected test framework's import syntax
- Import the actual function/module from `f.file` — write real imports, not mocks
- For auth findings: use supertest to call the actual route, check the response
- For XSS findings: call the sanitization function directly, assert the output
- For SQL injection: use the actual DB query function, pass a payload, assert it doesn't error or execute
- Add a `// TODO: remove VULNERABILITY test after fix is confirmed` comment on the failing test
- Output as a single test file named `security/<slug>-security.test.{js|ts|py}`
- Include the finding ID in a comment: `// agentic-security finding: <id>`

Write the complete file(s) and tell me where to put them.
