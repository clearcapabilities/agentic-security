---
description: Audit all webhook handlers for missing signature verification — Stripe, GitHub, Clerk, Svix, Resend, and generic providers.
---

Find webhook endpoint handlers that process payloads without verifying the provider's cryptographic signature. An unverified webhook endpoint accepts requests from anyone who knows the URL.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first, then /webhook-audit.');
  process.exit(0);
}

const wf = (scan.findings || []).filter(f =>
  (f.id || '').startsWith('webhook:') ||
  /webhook.*signature|missing.*signature.*verify|CWE-345/i.test(f.title || f.vuln || '')
);

console.log('');
console.log(W('Webhook Security Audit', '1'));
console.log('');

if (wf.length === 0) {
  console.log(W('  ✓  All webhook handlers verified or none detected.', '32'));
  console.log('');
  console.log('  Checked for missing signature verification on:');
  console.log('  • Stripe (constructEvent)');
  console.log('  • GitHub (X-Hub-Signature-256 HMAC)');
  console.log('  • Clerk (verifyWebhook)');
  console.log('  • Svix (wh.verify)');
  console.log('  • Resend (verifyWebhookSignature)');
  console.log('  • Twilio (validateRequest)');
  console.log('  • Generic HMAC signature patterns');
  console.log('');
  process.exit(0);
}

for (const f of wf) {
  console.log(W('[HIGH]', '31') + '  ' + (f.title || f.vuln));
  console.log('  ' + f.file + (f.line ? ':' + f.line : ''));
  console.log('  ' + W(f.description || '', '2'));
  console.log('');
  console.log('  Fix:');
  (f.remediation || '').split('\n').slice(0, 6).forEach(l => console.log('    ' + l));
  console.log('');
}

console.log(W('Why this matters', '1'));
console.log('  Without signature verification, anyone who discovers your webhook URL can:');
console.log('  • Fake a "payment succeeded" event → grant access without payment');
console.log('  • Fake a "user.created" event → create admin accounts');
console.log('  • Fake a "push" event → trigger CI/CD deploys with crafted payloads');
console.log('');
console.log('  Fix all:  /fix --one <finding-id>');
console.log('');
"
```

The fix requires accessing the **raw request body** (before JSON parsing) for signature verification. Most frameworks default to auto-parsing — you need to configure a raw body parser for the webhook route. See the remediation in each finding for provider-specific instructions.
