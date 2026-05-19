---
description: Security regression scorecard — shows finding counts over time, what was introduced vs fixed since the last scan, and which files regressed.
---

Show a trend line of your security posture across scans. Tracks what was fixed, what was introduced, and whether you're improving or regressing.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const HISTORY_FILE = '.agentic-security/scan-history.json';
let history = [];
try { history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch {}

// Also load current scan to show latest state
let currentScan = null;
try { currentScan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

console.log('');
console.log(W('Security Trend', '1'));
console.log('');

if (history.length === 0 && !currentScan) {
  console.log(W('  No scan history found.', '33'));
  console.log('  Run /scan --all a few times to build a trend.');
  console.log('  Each scan automatically appends to scan-history.json.');
  process.exit(0);
}

// If we have a current scan but no history, show current state
if (history.length < 2) {
  if (currentScan) {
    const f = currentScan.findings || [];
    const crit = f.filter(x=>x.severity==='critical').length;
    const high = f.filter(x=>x.severity==='high').length;
    const med = f.filter(x=>x.severity==='medium').length;
    const low = f.filter(x=>x.severity==='low').length;
    console.log(W('  Current state (1 scan — need 2+ for trend)', '2'));
    console.log('');
    console.log('  Total: ' + f.length + '  Critical: ' + W(crit, crit>0?'31':'32') + '  High: ' + W(high, high>0?'31':'32') + '  Med: ' + med + '  Low: ' + low);
    console.log('');
    console.log('  Run /scan --all again after fixing issues to see a trend.');
  } else {
    console.log(W('  Need at least 2 scans to show a trend.', '33'));
    console.log('  Run /scan --all now, fix some issues, then run again.');
  }
  process.exit(0);
}

// Show rolling history
const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36' };

console.log(W('  History (newest last):', '1'));
console.log('');

// Sparkline of total findings
const totals = history.map(h => h.total);
const maxTotal = Math.max(...totals, 1);
const barWidth = 20;
history.forEach((h, i) => {
  const date = new Date(h.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  const bar = '█'.repeat(Math.round((h.total / maxTotal) * barWidth));
  const prev = i > 0 ? history[i-1] : null;
  const delta = prev ? h.total - prev.total : null;
  const deltaStr = delta === null ? '' : delta > 0 ? W(' ▲'+delta, '31') : delta < 0 ? W(' ▼'+Math.abs(delta), '32') : W(' ━', '2');
  const critStr = h.critical > 0 ? W(' crit:' + h.critical, '31') : '';
  console.log('  ' + date.padEnd(8) + ' ' + W(bar.padEnd(barWidth), h.critical > 0 ? '31' : h.high > 0 ? '33' : '32') + ' ' + String(h.total).padStart(3) + deltaStr + critStr);
});
console.log('');

// Delta between last two scans
const prev = history[history.length - 2];
const curr = history[history.length - 1];
const prevIds = new Set(prev.ids || []);
const currIds = new Set(curr.ids || []);
const introduced = [...currIds].filter(id => !prevIds.has(id));
const fixed = [...prevIds].filter(id => !currIds.has(id));
const delta = curr.total - prev.total;
const critDelta = curr.critical - prev.critical;

console.log(W('  Since last scan:', '1'));
console.log('  Fixed:      ' + W(fixed.length + ' finding(s)', fixed.length > 0 ? '32' : '2'));
console.log('  Introduced: ' + W(introduced.length + ' finding(s)', introduced.length > 0 ? '31' : '2'));
console.log('  Net:        ' + W((delta > 0 ? '+' : '') + delta, delta < 0 ? '32' : delta > 0 ? '31' : '2'));
console.log('');

const improving = delta <= 0 && critDelta <= 0 && fixed.length > 0;
const regressing = introduced.length > 0 && (delta > 0 || critDelta > 0);

if (regressing) {
  console.log(W('  ⚠  Security regressed since last scan.', '31;1'));
  if (introduced.length > 0) {
    console.log('  New findings introduced:');
    introduced.slice(0, 5).forEach(id => console.log('    • ' + id.split(':').slice(0,3).join(':')));
    if (introduced.length > 5) console.log('    … and ' + (introduced.length - 5) + ' more');
  }
} else if (improving) {
  console.log(W('  ✓  Security improved since last scan. Keep going.', '32'));
} else {
  console.log(W('  ━  No change since last scan.', '2'));
}

console.log('');
console.log('  Streak: run /status for current streak info.');
console.log('  Fix regressions: /fix --all --high');
console.log('');
"
```

Each `/scan --all` run automatically appends a snapshot to `.agentic-security/scan-history.json`. The trend shows you whether security is improving or degrading across commits — like a fitness tracker for your codebase.
