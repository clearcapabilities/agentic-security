---
description: Find API endpoints missing rate limiting — auth, AI generation, payment, and contact endpoints that can be abused or cost you money.
---

Audit all API endpoints for missing rate limiting. Checks auth (brute-force risk), AI generation (cost explosion risk), payment (card-testing risk), and contact/form (spam risk) endpoints.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first.');
  process.exit(0);
}

const rlFindings = (scan.findings || []).filter(f =>
  (f.id || '').startsWith('rate-limit:') ||
  /rate.?limit|brute.?force|RATE_LIMIT/i.test(f.vuln || f.title || '')
);

// Also check if a rate-limit library is present in components
const components = scan.components || [];
const rlLibs = ['express-rate-limit','@upstash/ratelimit','rate-limiter-flexible','hono-rate-limiter','bottleneck'];
const installedRL = rlLibs.filter(lib => components.some(c => c.name === lib));

console.log('');
console.log(W('Rate Limiting Audit', '1'));
console.log('');

if (installedRL.length > 0) {
  console.log(W('  ✓  Rate-limit library detected: ', '32') + installedRL.join(', '));
  console.log('');
}

if (rlFindings.length === 0) {
  console.log(W('  ✓  No unprotected sensitive endpoints detected.', '32'));
  console.log('');
} else {
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };
  rlFindings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

  for (const f of rlFindings) {
    const color = sevColor[f.severity] || '0';
    console.log(W('[' + (f.severity || '?').toUpperCase() + ']', color) + '  ' + (f.title || f.vuln));
    console.log('  ' + f.file + (f.line ? ':' + f.line : ''));
    console.log('  ' + W(f.description, '2'));
    console.log('');
    console.log('  Fix: ' + f.remediation);
    console.log('');
  }
}

// Quick fix snippet
console.log(W('Quick-start: Add rate limiting', '1'));
console.log('');
console.log('  npm install @upstash/ratelimit @upstash/redis   # Serverless / Edge');
console.log('  npm install express-rate-limit                   # Node / Express');
console.log('');
console.log('  // Next.js API route — @upstash/ratelimit');
console.log('  import { Ratelimit } from \"@upstash/ratelimit\";');
console.log('  import { Redis } from \"@upstash/redis\";');
console.log('  const ratelimit = new Ratelimit({');
console.log('    redis: Redis.fromEnv(),');
console.log('    limiter: Ratelimit.slidingWindow(10, \"10 s\"),');
console.log('  });');
console.log('  const { success } = await ratelimit.limit(ip);');
console.log('  if (!success) return new Response(\"Too Many Requests\", { status: 429 });');
console.log('');
"
```

For AI endpoints in particular: even a single attacker without a rate limit can send thousands of requests per minute, generating hundreds of dollars in API costs in minutes. Add rate limiting before any AI feature goes live.
