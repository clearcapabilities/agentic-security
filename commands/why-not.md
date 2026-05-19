---
description: Recall spot-check for a CWE — show which sources, sinks, and sanitizers the engine considered for that CWE in the current scan, and explain why no finding was reported. Surfaces gaps in the catalog.
argument-hint: "<CWE> (e.g. CWE-89, or just 89, or 'sql-injection')"
---

For a CWE the user *expects* the scanner to flag but didn't, this command opens the books: it shows which sources, sinks, and sanitizers from that CWE's family the engine considered, and explains why nothing fired. Useful when chasing recall gaps.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');

const arg = (process.argv[1] || '').trim();
if (!arg) {
  console.error('Usage: /why-not <CWE> (e.g. CWE-89 or 89 or sql-injection)');
  process.exit(1);
}

let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch (e) { console.error('No last-scan.json found. Run /scan --all first.'); process.exit(1); }

const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;

// Resolve arg → CWE + family
const CWE_TO_FAMILY = {
  'CWE-89': 'sql-injection', 'CWE-79': 'xss', 'CWE-78': 'command-injection',
  'CWE-22': 'path-traversal', 'CWE-918': 'ssrf', 'CWE-611': 'xxe',
  'CWE-502': 'insecure-deserialization', 'CWE-94': 'code-injection',
  'CWE-915': 'mass-assignment', 'CWE-1321': 'prototype-pollution',
  'CWE-352': 'csrf', 'CWE-367': 'toctou', 'CWE-90': 'ldap-injection',
  'CWE-643': 'xpath-injection', 'CWE-943': 'nosql-injection',
  'CWE-601': 'open-redirect',  'CWE-798': 'hardcoded-secret',
  'CWE-327': 'weak-crypto', 'CWE-330': 'weak-rng', 'CWE-613': 'jwt-no-exp',
};
const FAMILY_ALIAS = { sql:'sql-injection', xss:'xss', cmd:'command-injection',
                       command:'command-injection', csrf:'csrf', ssrf:'ssrf',
                       idor:'idor', xxe:'xxe', deser:'insecure-deserialization' };

let cwe = null, family = null;
const m = arg.match(/(?:CWE[-_]?)?(\\d+)/i);
if (m) {
  cwe = 'CWE-' + m[1];
  family = CWE_TO_FAMILY[cwe] || null;
} else {
  family = FAMILY_ALIAS[arg.toLowerCase()] || arg.toLowerCase();
  for (const [k, v] of Object.entries(CWE_TO_FAMILY)) if (v === family) { cwe = k; break; }
}

console.log('');
console.log(W('━━━ Why not: ' + (cwe || family || arg) + ' ━━━', '1'));
console.log('');

// 1. Were there findings of that family/CWE?
const matched = (scan.findings || []).filter(f =>
  (cwe && f.cwe === cwe) || (family && f.family === family));
if (matched.length) {
  console.log(W('Actually, this CWE WAS flagged — ' + matched.length + ' finding(s):', '32'));
  for (const f of matched.slice(0, 5)) {
    console.log('  · ' + f.vuln + '  →  ' + (f.file || '?') + ':' + (f.line || '?'));
  }
  if (matched.length > 5) console.log('  · ... and ' + (matched.length - 5) + ' more.');
  process.exit(0);
}

// 2. Were sources/sinks for that family seen but not linked?
const allSrc = scan.sources || [];
const allSink = scan.sinks || [];
const sourcesOfFamily = allSrc.filter(s => (s.family || '').includes(family || '_NONE_'));
const sinksOfFamily   = allSink.filter(s => (s.family || '').includes(family || '_NONE_'));

console.log(W('Considered for this CWE:', '1'));
console.log('  Sources matching this family:    ' + sourcesOfFamily.length);
console.log('  Sinks matching this family:      ' + sinksOfFamily.length);

const suppressions = (scan.suppressions || []).filter(s => {
  const r = (s.reason || '').toLowerCase();
  return r.includes(family || '_NONE_') || r.includes(cwe?.toLowerCase() || '_NONE_');
});
console.log('  Suppressed candidate findings:   ' + suppressions.length);
console.log('');

// 3. Why no finding?
console.log(W('Why no finding:', '1'));
if (sourcesOfFamily.length === 0 && sinksOfFamily.length === 0) {
  console.log('  · The engine did not detect any sources OR sinks of this family in your code.');
  console.log('    Either the code path doesn\\'t exist, or the catalog doesn\\'t know about your');
  console.log('    framework\\'s entry points / sinks. Consider adding a custom rule via /query');
  console.log('    or .agentic-security/rules.yml.');
} else if (sourcesOfFamily.length === 0) {
  console.log('  · Sinks present, but no untrusted source flows into them. The sinks are likely');
  console.log('    fed by constants or by data already validated. Check the engine sources file');
  console.log('    if you expected a particular source to be recognized.');
} else if (sinksOfFamily.length === 0) {
  console.log('  · Sources present, but they don\\'t flow into any sink of this family.');
} else if (suppressions.length > 0) {
  console.log('  · Sources AND sinks were seen, and candidate findings WERE generated, but');
  console.log('    suppressed. Top suppression reasons:');
  const byReason = new Map();
  for (const s of suppressions.slice(0, 50)) byReason.set(s.reason, (byReason.get(s.reason) || 0) + 1);
  for (const [r, n] of [...byReason.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5)) {
    console.log('       · ' + r + ' (' + n + 'x)');
  }
} else {
  console.log('  · Sources and sinks both seen, but no taint path linked them across functions.');
  console.log('    The cross-file taint analyzer didn\\'t resolve a path. This is a recall gap —');
  console.log('    consider posting the file path so it can be added to the test corpus.');
}
console.log('');
" -- "$1"
```

Print the output as-is. If the user names a CWE you don't have a family mapping for, fall back to the family slug derived from their input.
