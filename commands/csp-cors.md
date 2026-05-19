---
description: Generate exact Content-Security-Policy and CORS headers for your stack — reads your actual dependencies and config, outputs copy-paste-ready header blocks.
---

Generate a working Content-Security-Policy and CORS configuration tailored to this project's actual stack and domains.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

// Gather stack facts
const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const deps = pkg ? { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) } : {};
const d = n => Object.keys(deps).some(k => k.toLowerCase().includes(n.toLowerCase()));

const vercelJson = (() => { try { return JSON.parse(fs.readFileSync('vercel.json','utf8')); } catch { return null; } })();
const nextCfg = (() => { try { return fs.readFileSync('next.config.js','utf8') || fs.readFileSync('next.config.ts','utf8'); } catch { return ''; } })();

// Detect external domains the app calls
const sources = {
  stripe: d('stripe'),
  supabase: d('@supabase'),
  clerk: d('clerk') || d('@clerk'),
  resend: d('resend'),
  openai: d('openai'),
  anthropic: d('@anthropic-ai'),
  google: d('@google'),
  mapbox: d('mapbox'),
  twilio: d('twilio'),
  analytics: d('@segment') || d('mixpanel') || d('posthog') || d('@vercel/analytics'),
  intercom: d('@intercom') || fs.existsSync('.') && Object.keys(deps).some(k => /intercom/i.test(k)),
  sentry: d('@sentry'),
};

const deployment = {
  vercel: !!vercelJson || d('next'),
  railway: fs.existsSync('railway.json') || fs.existsSync('railway.toml'),
  fly: fs.existsSync('fly.toml'),
};

const appUrl = process.env.VERCEL_URL || process.env.RAILWAY_PUBLIC_DOMAIN ||
  (pkg && pkg.homepage) || 'https://your-app.com';

console.log('');
console.log(W('CSP & CORS Generator', '1'));
console.log('');
console.log('Stack detected:');
Object.entries(sources).filter(([,v])=>v).forEach(([k])=>console.log('  • ' + k));
console.log('');
console.log('App URL (override with APP_URL env var): ' + appUrl);
console.log('');

// Output structured data for Claude to generate the policies
console.log(JSON.stringify({
  appUrl,
  framework: d('next') ? 'nextjs' : d('express') ? 'express' : d('fastify') ? 'fastify' : d('hono') ? 'hono' : 'unknown',
  deployment: Object.entries(deployment).filter(([,v])=>v).map(([k])=>k)[0] || 'unknown',
  externalServices: Object.entries(sources).filter(([,v])=>v).map(([k])=>k),
  hasNextConfig: fs.existsSync('next.config.js') || fs.existsSync('next.config.ts') || fs.existsSync('next.config.mjs'),
  hasVercelJson: !!vercelJson,
  existingHeaders: nextCfg.includes('X-Frame-Options') || (vercelJson && JSON.stringify(vercelJson).includes('X-Frame-Options')),
}, null, 2));
"
```

Using the JSON above, generate two things and output them as copy-paste-ready code blocks:

**1. Content-Security-Policy header value** — a complete CSP string that:
- Has `default-src 'self'`
- Adds `script-src` domains for each detected service (Stripe: `js.stripe.com`, Clerk: `*.clerk.accounts.dev`, Supabase: the project URL, analytics scripts, etc.)
- Adds `connect-src` for each API domain (Supabase: `*.supabase.co`, OpenAI: `api.openai.com`, etc.)
- Uses `img-src 'self' data: blob:` plus CDN domains for any image services
- Does NOT use `unsafe-inline` or `unsafe-eval` unless absolutely required
- Explain any relaxations needed

**2. CORS configuration** for the detected framework:
- `allowedOrigins` list (the app URL + any known frontend domains)
- Allowed methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
- Allow credentials: true (with caveat about wildcard origin)
- Preflight cache: 86400

For Next.js: output the `headers()` block for `next.config.js`.
For Express: output the `cors()` options object.
For Vercel: output the `headers` array for `vercel.json`.

End with: "Test your CSP with the Chrome DevTools Security panel and fix any console errors about blocked resources."
