---
description: Audit database security — Supabase RLS, raw SQL injection, exposed admin APIs, and direct DB connections that bypass row-level policies.
---

Run a targeted database security audit. Covers Supabase Row-Level Security, service-role key exposure, admin API misuse, raw PostgreSQL connections that bypass RLS, and SQL files with tables that lack RLS policies.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');

const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first, then /db-audit.');
  process.exit(0);
}

const DB_PREFIXES = ['db-rls:', 'sql-injection', 'nosql', 'NoSQL', 'SQL Injection', 'orm-raw'];
const dbFindings = (scan.findings || []).filter(f =>
  DB_PREFIXES.some(p => (f.id || '').startsWith(p) || (f.vuln || '').includes(p.replace(/[-:]/g, ' '))) ||
  /supabase|rls|row.level|service.role|bypass.*rls|postgres.*handler/i.test(f.title || f.vuln || '')
);

console.log('');
console.log(W('Database Security Audit', '1'));
console.log('');

if (dbFindings.length === 0) {
  console.log(W('  ✓  No database security issues detected.', '32'));
  console.log('');
  console.log('  Checked:');
  console.log('  • Supabase service-role key exposure');
  console.log('  • NEXT_PUBLIC_ vars leaking service keys');
  console.log('  • auth.admin API called client-side');
  console.log('  • bypassRowLevelSecurity() in queries');
  console.log('  • SQL tables created without RLS');
  console.log('  • Raw PostgreSQL connections in request handlers');
  console.log('  • SQL injection patterns');
  console.log('');
  process.exit(0);
}

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
dbFindings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };

for (const f of dbFindings) {
  const color = sevColor[f.severity] || '0';
  console.log(W('[' + (f.severity || '?').toUpperCase() + ']', color) + '  ' + (f.title || f.vuln));
  console.log('  File: ' + f.file + (f.line ? ':' + f.line : ''));
  console.log('  ' + W(f.description || '', '2'));
  console.log('');
  console.log('  Fix: ' + (f.remediation || f.fix?.description || 'See /explain ' + (f.id || '')));
  console.log('');
}

const crit = dbFindings.filter(f => f.severity === 'critical').length;
const high = dbFindings.filter(f => f.severity === 'high').length;
console.log(W('Summary', '1'));
console.log('  ' + dbFindings.length + ' database finding(s): ' + crit + ' critical, ' + high + ' high');
if (crit > 0) {
  console.log('  ' + W('Critical findings require immediate action — data may already be exposed.', '31'));
}
console.log('');
console.log('  Fix all:      /fix --all');
console.log('  Fix one:      /fix --one <finding-id>');
console.log('  Validate:     /validate-findings <finding-id>');
console.log('');
"
```

Review each finding carefully. Critical RLS and service-role findings should be fixed before the next deploy — data exposure from a missing RLS policy can affect every row in the affected table for every user.
