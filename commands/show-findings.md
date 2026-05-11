---
description: Print the findings from the last scan. No re-scan — reads .agentic-security/last-scan.json.
argument-hint: "[--severity critical|high|medium|low]"
---

Print every finding from the most recent scan, grouped by severity. No re-scan is performed — this reads `.agentic-security/last-scan.json`.

```bash
node -e "
const fs = require('node:fs');
const path = '.agentic-security/last-scan.json';
if (!fs.existsSync(path)) {
  console.error('No scan on file. Run /scan-all first.');
  process.exit(1);
}
const args = process.argv.slice(1);
const sevArg = (args.find(a => a.startsWith('--severity=')) || args[args.indexOf('--severity') + 1] || '').replace('--severity=', '');
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const floor = RANK[sevArg] ?? 0;
const scan = JSON.parse(fs.readFileSync(path, 'utf8'));
const all = (scan.findings || []).filter(f => (RANK[f.severity] ?? 0) >= floor);
if (!all.length) {
  console.log('No findings at or above ' + (sevArg || 'info') + '. Last scan: ' + (scan.scannedAt || 'unknown') + '.');
  process.exit(0);
}
const order = ['critical', 'high', 'medium', 'low', 'info'];
const ICONS = { critical: '🛑', high: '⚠️ ', medium: '·', low: '·', info: '·' };
console.log('Findings from last scan (' + (scan.scannedAt || 'unknown') + ')');
console.log('');
for (const sev of order) {
  const rows = all.filter(f => f.severity === sev);
  if (!rows.length) continue;
  console.log(sev.toUpperCase() + ' — ' + rows.length);
  for (const f of rows) {
    const loc = (f.file || '') + (f.line ? ':' + f.line : '');
    console.log('  ' + (ICONS[sev] || '·') + ' [' + (f.id || '').slice(0, 8) + '] ' + (f.vuln || f.title || '') + '  ' + loc);
    if (f.description) console.log('      ' + f.description.split('\\n')[0]);
  }
  console.log('');
}
console.log('Total: ' + all.length + (sevArg ? ' (filtered to ' + sevArg + '+)' : ''));
console.log('Next: /fix-all --severity ' + (sevArg || 'critical') + '  to remediate.');
" -- ${1} ${2}
```

## How to respond to the user

The scanner already printed the findings. Don't repeat them — just confirm the next step:

- If there are findings: suggest `/fix-all --severity <tier>` matching what's worth fixing.
- If clean: confirm and stop.

🛡  agentic-security · created by ClearCapabilities.Com
