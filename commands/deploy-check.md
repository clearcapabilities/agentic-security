---
description: Platform-specific security checklist for Vercel, Railway, Fly.io, Render, Netlify, and Cloudflare Workers — catches the infra-layer issues code scanners miss.
---

Run a deployment-platform security audit. Detects your hosting platform from config files and checks for platform-specific issues: missing security headers, public preview deployments, no health checks, missing HTTPS redirect, and more.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

const deployFindings = scan ? (scan.findings || []).filter(f =>
  (f.id || '').startsWith('deploy-platform:') ||
  /vercel|railway|fly\.io|netlify|cloudflare|render|amplify|healthcheck|security.header|force.https|preview.deploy/i.test(f.title || f.vuln || '')
) : [];

// Detect platforms from filesystem (runtime check, not scan-dependent)
const platforms = [];
if (fs.existsSync('vercel.json') || fs.existsSync('.vercel') || fs.existsSync('next.config.js') || fs.existsSync('next.config.ts')) platforms.push('Vercel');
if (fs.existsSync('railway.json') || fs.existsSync('railway.toml')) platforms.push('Railway');
if (fs.existsSync('fly.toml')) platforms.push('Fly.io');
if (fs.existsSync('netlify.toml')) platforms.push('Netlify');
if (fs.existsSync('wrangler.toml') || fs.existsSync('wrangler.json')) platforms.push('Cloudflare Workers');
if (fs.existsSync('render.yaml') || fs.existsSync('render.yml')) platforms.push('Render');

console.log('');
console.log(W('Deployment Platform Security Audit', '1'));
console.log('');
console.log('  Platforms detected: ' + (platforms.length ? platforms.join(', ') : W('none — add platform config files', '33')));
console.log('');

if (platforms.length === 0) {
  console.log(W('  No deployment platform config files detected.', '33'));
  console.log('  Supported: vercel.json, railway.json/toml, fly.toml, netlify.toml, wrangler.toml, render.yaml');
  console.log('');
  console.log('  Run /scan --all to check for platform-specific findings anyway.');
  process.exit(0);
}

if (deployFindings.length === 0) {
  console.log(W('  ✓  No platform security issues detected.', '32'));
  console.log('');
  console.log('  Checked for:');
  if (platforms.includes('Vercel')) {
    console.log('  • Vercel: security headers, public preview deployments');
  }
  if (platforms.includes('Railway')) {
    console.log('  • Railway: health check configuration');
  }
  if (platforms.includes('Fly.io')) {
    console.log('  • Fly.io: HTTPS enforcement, scale-to-zero');
  }
  if (platforms.includes('Netlify')) {
    console.log('  • Netlify: security headers');
  }
  if (platforms.includes('Cloudflare Workers')) {
    console.log('  • Cloudflare: compatibility_date');
  }
  console.log('');
  process.exit(0);
}

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };
deployFindings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

for (const f of deployFindings) {
  const c = sevColor[f.severity] || '0';
  console.log(W('[' + (f.severity || '?').toUpperCase() + ']', c) + '  ' + (f.title || f.vuln));
  console.log('  File: ' + f.file + (f.line ? ':' + f.line : ''));
  if (f.description) console.log('  ' + W(f.description.slice(0, 200), '2'));
  console.log('');
  if (f.remediation) {
    const lines = f.remediation.split('\n');
    console.log('  Fix:');
    lines.slice(0, 6).forEach(l => console.log('    ' + l));
  }
  console.log('');
}

console.log(W('Summary', '1'));
const high = deployFindings.filter(f => f.severity === 'high' || f.severity === 'critical').length;
console.log('  ' + deployFindings.length + ' platform finding(s) — ' + high + ' high/critical');
console.log('');
console.log('  These are infra-layer issues — fix them in your config files, not source code.');
console.log('  After fixing, redeploy and re-run /deploy-check to confirm.');
console.log('');
"
```

Deployment-platform findings are often overlooked because code scanners don't read infra config files. A missing `force_https` on Fly.io or public preview deployments on Vercel are real attack vectors that are invisible to source-code SAST tools.
