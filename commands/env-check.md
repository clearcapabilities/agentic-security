---
description: Audit environment variable hygiene — NEXT_PUBLIC_ leaks, .env.example with real values, hardcoded fallbacks, and missing .gitignore entries.
---

Check environment variable hygiene across the project. Detects client-side exposure of secrets via NEXT_PUBLIC_, real credentials in example env files, hardcoded fallback values in source, and .env files not protected by .gitignore.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const cp = require('child_process');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

// Load scan findings
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

const envFindings = scan ? (scan.findings || []).filter(f =>
  (f.id || '').startsWith('env-hygiene:') ||
  /NEXT_PUBLIC.*secret|env.*example.*real|dotenv.*prod|hardcoded.*fallback/i.test(f.title || '')
) : [];

// Runtime checks (not scanner-dependent)
const checks = [];

// .gitignore check
const gitignore = (() => { try { return fs.readFileSync('.gitignore', 'utf8'); } catch { return ''; } })();
const envPatterns = ['.env', '.env.local', '.env.production', '.env.development'];
const missingFromGitignore = envPatterns.filter(p => !gitignore.includes(p) && fs.existsSync(p));

if (missingFromGitignore.length > 0) {
  checks.push({ severity: 'critical', label: '.env files not in .gitignore', detail: missingFromGitignore.join(', ') + ' exist but are not excluded in .gitignore' });
}

// Files tracked by git that look like .env
const trackedEnv = (() => {
  try {
    const out = cp.execSync('git ls-files', { encoding: 'utf8', stdio: ['ignore','pipe','ignore'] });
    return out.split('\n').filter(l => /^\.env(\.|$)/i.test(l.trim()));
  } catch { return []; }
})();
if (trackedEnv.length > 0) {
  checks.push({ severity: 'critical', label: '.env files committed to git', detail: trackedEnv.join(', ') + ' — these are tracked in git history. Even if removed, the history must be purged.' });
}

// Check for NEXT_PUBLIC_ in .env files
const envFiles = ['.env', '.env.local', '.env.production', '.env.development', '.env.staging'];
for (const ef of envFiles) {
  try {
    const content = fs.readFileSync(ef, 'utf8');
    const sensitivePublic = content.match(/^NEXT_PUBLIC_\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE|SIGNING|WEBHOOK|SALT)\w*\s*=/gim) || [];
    if (sensitivePublic.length > 0) {
      checks.push({ severity: 'critical', label: \`\${ef}: NEXT_PUBLIC_ secret variable\`, detail: sensitivePublic.slice(0, 3).map(m => m.split('=')[0].trim()).join(', ') + ' will be bundled into client JavaScript' });
    }
  } catch {}
}

// .env.example with non-placeholder values
try {
  const exContent = fs.readFileSync('.env.example', 'utf8');
  const lines = exContent.split('\n');
  const realLines = lines.filter((l, i) => {
    if (!l.trim() || l.trim().startsWith('#')) return false;
    const eq = l.indexOf('=');
    if (eq === -1) return false;
    const val = l.slice(eq + 1).trim().replace(/^['\`\"]|['\`\"]$/g, '');
    return val && val.length >= 8 && !/^(?:your_|<|changeme|placeholder|xxx|todo|replace|example|sample|test|dummy|fake|n\/a)/i.test(val);
  });
  if (realLines.length > 0) {
    checks.push({ severity: 'high', label: '.env.example contains real-looking values', detail: realLines.length + ' line(s) with non-placeholder values — may contain real credentials in git history' });
  }
} catch {}

// Print results
console.log('');
console.log(W('Environment Hygiene Check', '1'));
console.log('');

const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36' };
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };

const allIssues = [
  ...checks.map(c => ({ ...c, source: 'runtime' })),
  ...envFindings.map(f => ({ severity: f.severity, label: f.title || f.vuln, detail: f.description, source: 'scan' }))
].sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

if (allIssues.length === 0) {
  console.log(W('  ✓  Environment hygiene is clean.', '32'));
  console.log('');
  console.log('  Checked:');
  console.log('  • .env files in .gitignore');
  console.log('  • .env files not committed to git');
  console.log('  • NEXT_PUBLIC_ vars for secret names');
  console.log('  • .env.example with real values');
  console.log('  • Hardcoded fallbacks in source');
} else {
  for (const issue of allIssues) {
    const c = sevColor[issue.severity] || '0';
    console.log(W('[' + (issue.severity || '?').toUpperCase() + ']', c) + '  ' + issue.label);
    if (issue.detail) console.log('  ' + W(issue.detail.slice(0, 200), '2'));
    console.log('');
  }
  const crit = allIssues.filter(i => i.severity === 'critical').length;
  console.log(W('Summary', '1'));
  console.log('  ' + allIssues.length + ' issue(s) — ' + crit + ' critical');
  if (crit > 0) {
    console.log('  ' + W('Fix critical issues before next deploy — secrets may already be exposed.', '31'));
  }
}
console.log('');
console.log('  Add to .gitignore:  /fix --one <id>   or manually add .env entries');
console.log('  Rotate secrets:     /rotate-secret <value-or-id>');
console.log('');
"
```

If any .env files are already committed to git, rotating the secrets is not enough — you also need to purge them from git history (`git filter-repo` or BFG Repo Cleaner) and rotate every secret that was in those files.
