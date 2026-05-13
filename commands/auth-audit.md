---
description: Deep-audit your auth provider configuration — Clerk, NextAuth, Auth0, Lucia, and generic OAuth for dangerous flags, missing secrets, and CSRF gaps.
---

Audit the authentication layer for provider-specific misconfigurations. Covers: dangerous email account linking, trustHost CSRF bypass, missing NEXTAUTH_SECRET, weak session secrets, hardcoded OAuth client secrets, Clerk public route misconfig, and insecure cookie flags.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first, then /auth-audit.');
  process.exit(0);
}

const AUTH_PREFIXES = ['auth-provider:', 'authz:', 'jwt-exp:'];
const AUTH_VULS = /jwt|session fixation|oauth|pkce|csrf|algorithm confusion|alg.none|trust.host|clerk|nextauth|auth.*secret|cookie.+secure/i;
const authFindings = (scan.findings || []).filter(f =>
  AUTH_PREFIXES.some(p => (f.id || '').startsWith(p)) ||
  AUTH_VULS.test(f.title || f.vuln || '')
);

console.log('');
console.log(W('Auth Provider Security Audit', '1'));
console.log('');

if (authFindings.length === 0) {
  console.log(W('  ✓  No auth provider misconfigurations detected.', '32'));
  console.log('');
  console.log('  Checked:');
  console.log('  • allowDangerousEmailAccountLinking');
  console.log('  • trustHost: true (CSRF bypass)');
  console.log('  • Missing NEXTAUTH_SECRET');
  console.log('  • Weak or hardcoded session secrets');
  console.log('  • Hardcoded OAuth client secrets');
  console.log('  • CSRF protection disabled');
  console.log('  • Clerk: sensitive routes in publicRoutes');
  console.log('  • Session cookies without secure/sameSite');
  console.log('  • JWT alg:none / missing algorithms option');
  console.log('  • JWT without expiry');
  console.log('');
  process.exit(0);
}

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };
authFindings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

for (const f of authFindings) {
  const color = sevColor[f.severity] || '0';
  console.log(W('[' + (f.severity || '?').toUpperCase() + ']', color) + '  ' + (f.title || f.vuln));
  console.log('  ' + f.file + (f.line ? ':' + f.line : ''));
  if (f.description) console.log('  ' + W(f.description.slice(0, 200), '2'));
  console.log('');
  if (f.remediation) console.log('  Fix: ' + f.remediation.slice(0, 300));
  console.log('');
}

const crit = authFindings.filter(f => f.severity === 'critical').length;
const high = authFindings.filter(f => f.severity === 'high').length;
console.log(W('Summary', '1'));
console.log('  ' + authFindings.length + ' auth finding(s) — ' + crit + ' critical, ' + high + ' high');
console.log('');
console.log('  Fix all:      /fix --all --high');
console.log('  Explain one:  /explain <finding-id>');
console.log('');
"
```

Auth misconfigurations are the #1 way apps get compromised. Address every high/critical finding before going live. `allowDangerousEmailAccountLinking` and `trustHost: true` are account-takeover vulnerabilities that require zero user interaction from the attacker.
