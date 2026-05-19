---
description: Generate a GitHub Actions security gate that runs the scanner on every PR and fails the build on critical/high findings.
argument-hint: "[--severity critical|high|medium] [--comment] [--apply]"
---

Generate a `.github/workflows/security.yml` that integrates the scanner into your CI pipeline. PRs with critical findings fail the build before merge.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const args = process.argv.slice(1);
const severity = args.find(a => /^(critical|high|medium)$/.test(a)) || 'high';
const shouldApply = args.includes('--apply');
const addComment = args.includes('--comment');

// Detect project type
const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const isNode = !!pkg;
const nodeVersion = pkg?.engines?.node?.replace(/[^0-9.]/g,'').split('.')[0] || '20';
const hasPython = fs.existsSync('requirements.txt') || fs.existsSync('pyproject.toml');
const installCmd = isNode ? 'npm ci' : hasPython ? 'pip install -r requirements.txt' : 'echo no install';
const testCmd = isNode ? (pkg?.scripts?.test ? 'npm test' : 'echo no tests') : hasPython ? 'pytest' : 'echo no tests';

// Check if workflow already exists
const wfPath = '.github/workflows/security.yml';
const exists = fs.existsSync(wfPath);

const pluginVersion = '0.31.1';

const yaml = \`name: Security Scan

on:
  pull_request:
    branches: [main, master, develop]
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write  # needed for PR comments
  security-events: write  # needed for SARIF upload

jobs:
  security:
    name: agentic-security scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '\${nodeVersion}'
          cache: '\${isNode ? 'npm' : 'none'}'

      - name: Install dependencies
        run: \${installCmd}

      - name: Install agentic-security scanner
        run: |
          npm install -g @clearcapabilities/agentic-security-scanner@\${pluginVersion} 2>/dev/null || \\
          npx --yes @clearcapabilities/agentic-security-scanner@\${pluginVersion} --version || \\
          echo 'Scanner install attempted'

      - name: Run security scan
        id: scan
        run: |
          node scanner/dist/agentic-security.mjs scan . \\
            --format sarif \\
            --output security-results.sarif \\
            --format json \\
            --output security-results.json \\
            --no-network \\
          || true

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
        continue-on-error: true

\${addComment ? \`      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let body = '## 🛡 Security Scan Results\\n';
            try {
              const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));
              const findings = results.findings || [];
              const crit = findings.filter(f => f.severity === 'critical').length;
              const high = findings.filter(f => f.severity === 'high').length;
              const grade = crit > 0 ? 'F' : high > 2 ? 'D' : high > 0 ? 'C' : 'B';
              body += \\\`Grade: **\\\${grade}** | Critical: \\\${crit} | High: \\\${high} | Total: \\\${findings.length}\\\\n\\\\n\\\`;
              if (crit > 0 || high > 0) {
                body += '### Findings requiring attention\\n';
                findings.filter(f => f.severity === 'critical' || f.severity === 'high')
                  .slice(0, 10)
                  .forEach(f => { body += \\\`- [\\\${f.severity.toUpperCase()}] \\\${f.vuln || f.title} — \\\${f.file}:\\\${f.line}\\\\n\\\`; });
              } else {
                body += '✅ No critical or high findings.';
              }
            } catch { body += 'Scan results unavailable.'; }
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body,
            });
\` : ''}
      - name: Fail on \${severity}+ findings
        run: |
          node -e "
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));
            const findings = results.findings || [];
            const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            const threshold = sevOrder['\${severity}'] ?? 1;
            const blocking = findings.filter(f => (sevOrder[f.severity] ?? 99) <= threshold);
            if (blocking.length > 0) {
              console.error('Security gate failed: ' + blocking.length + ' \${severity}+ finding(s)');
              blocking.slice(0, 5).forEach(f => console.error('  [' + f.severity + '] ' + (f.vuln || f.title) + ' — ' + f.file + ':' + f.line));
              process.exit(1);
            }
            console.log('Security gate passed.');
          "
\`;

console.log('');
console.log(W('GitHub Actions Security Gate', '1'));
console.log('  Blocks on: ' + severity + ' and above');
console.log('  PR comments: ' + (addComment ? 'enabled' : 'disabled (add --comment to enable)'));
console.log('  File: ' + wfPath);
console.log('');

if (shouldApply) {
  if (exists) {
    console.log(W('  ⚠  ' + wfPath + ' already exists. Skipping to avoid overwrite.', '33'));
    console.log('  Delete it first or review and merge manually.');
  } else {
    fs.mkdirSync('.github/workflows', { recursive: true });
    fs.writeFileSync(wfPath, yaml);
    console.log(W('  ✓  Created ' + wfPath, '32'));
  }
} else {
  console.log(W('  DRY RUN — pass --apply to write the file.', '33'));
  console.log('');
  console.log('  Generated workflow:');
  console.log('');
  console.log(yaml.split('\n').map(l => '  ' + l).join('\n'));
}
console.log('');
" -- "$@"
```

Pass `--apply` to write the file, `--comment` to enable PR review comments, and `--severity critical|high|medium` to set the failure threshold. Default threshold is `high` — critical+high findings fail the build.

After applying: `git add .github/workflows/security.yml && git commit -m "ci: add security gate"`.
