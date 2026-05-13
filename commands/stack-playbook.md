---
description: Generate a security playbook tailored to your exact tech stack — opinionated, copy-paste-ready steps for the libraries you actually use.
---

Detect the project's tech stack and generate a targeted security checklist. Unlike generic security guides, this playbook is specific to the frameworks, ORMs, auth providers, and services this project uses.

```bash
node -e "
const fs = require('fs');
const path = require('path');

// Detect platform
const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.resolve('.');
let scannerPath = path.join(pluginRoot, 'scanner', 'dist', 'agentic-security.mjs');

// Read last scan for stack context
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

// Detect stack from package.json
const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json', 'utf8')); } catch { return null; } })();
const deps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};
const d = n => Object.keys(deps).some(k => k.toLowerCase() === n.toLowerCase());
const dp = n => Object.keys(deps).some(k => k.toLowerCase().includes(n.toLowerCase()));

const stack = [];
if (d('next')) stack.push('Next.js');
if (dp('@supabase')) stack.push('Supabase');
if (d('stripe')) stack.push('Stripe');
if (dp('clerk')) stack.push('Clerk');
if (d('next-auth') || dp('@auth/core')) stack.push('NextAuth');
if (d('prisma') || dp('@prisma/client')) stack.push('Prisma');
if (d('drizzle-orm')) stack.push('Drizzle ORM');
if (dp('openai')) stack.push('OpenAI');
if (dp('@anthropic-ai')) stack.push('Anthropic');
if (dp('langchain') || dp('@langchain')) stack.push('LangChain');
if (d('express')) stack.push('Express');
if (d('stripe')) stack.push('Stripe');
if (d('mongoose') || d('mongodb')) stack.push('MongoDB');
if (dp('firebase')) stack.push('Firebase');
if (d('trpc') || dp('@trpc/server')) stack.push('tRPC');

const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

console.log('');
console.log(W('Stack detected: ' + (stack.join(', ') || 'unknown'), '1'));
console.log('');

// Pull stack-playbook findings from last scan if available
const playbookFindings = scan ? (scan.findings || []).filter(f => f.id && f.id.startsWith('stack-playbook:')) : [];
if (playbookFindings.length > 0) {
  let currentStack = '';
  for (const f of playbookFindings) {
    const stackName = (f.title.match(/\[([^\]]+) Security Checklist\]/) || [])[1] || 'General';
    if (stackName !== currentStack) {
      currentStack = stackName;
      console.log(W('── ' + stackName + ' ──────────────────────────────', '36;1'));
    }
    console.log('  □  ' + f.description);
    console.log('');
  }
} else {
  if (stack.length === 0) {
    console.log(W('No recognisable stack detected.', '33'));
    console.log('  Supported: Next.js, Supabase, Clerk, NextAuth, Prisma, Stripe, OpenAI, Anthropic, Express, MongoDB, tRPC');
    console.log('');
    console.log('  Run /scan --all first to generate a full playbook.');
  } else {
    console.log(W('Run /scan --all to generate a detailed security playbook for your stack.', '33'));
    console.log('  The scanner will analyse your stack and return prioritised, copy-paste-ready steps.');
  }
}
console.log('');
"
```

After running the script above, review each checklist item and apply any that aren't already implemented. Use `/explain <item>` for a plain-English breakdown of any item, or `/fix --one <id>` for auto-remediation where available.
