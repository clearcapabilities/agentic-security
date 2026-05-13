---
description: Guided migration from scattered env vars to a proper secrets vault — Doppler, Infisical, or platform-native secrets management.
argument-hint: "[doppler|infisical|vercel|railway]"
---

Guide a migration from `.env` files and scattered environment variables to a proper secrets vault. Detects your current secrets, counts them, and gives step-by-step migration commands for your chosen vault.

```bash
node -e "
const fs = require('fs');
const cp = require('child_process');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

const target = (process.argv[1] || '').trim() || null;

// Collect all env vars across env files
const envFiles = ['.env', '.env.local', '.env.production', '.env.staging', '.env.development'];
const allVars = new Map();
for (const ef of envFiles) {
  try {
    const content = fs.readFileSync(ef, 'utf8');
    content.split('\n').forEach(line => {
      if (!line.trim() || line.startsWith('#')) return;
      const eq = line.indexOf('=');
      if (eq === -1) return;
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim();
      if (!allVars.has(key)) allVars.set(key, { key, val, source: ef });
    });
  } catch {}
}

// Classify sensitivity
const SENSITIVE_RE = /secret|key|token|password|pass|credential|api|private|signing|webhook|salt|seed|database|db_url|dsn/i;
const secrets = [...allVars.values()].filter(v => SENSITIVE_RE.test(v.key));
const configs = [...allVars.values()].filter(v => !SENSITIVE_RE.test(v.key));

// Detect deployment platform
const hasVercel = fs.existsSync('vercel.json') || fs.existsSync('.vercel');
const hasRailway = fs.existsSync('railway.json') || fs.existsSync('railway.toml');
const hasFly = fs.existsSync('fly.toml');

const platformSuggestion = hasVercel ? 'vercel' : hasRailway ? 'railway' : 'doppler';
const vault = target || platformSuggestion;

console.log('');
console.log(W('Secrets Vault Migration Wizard', '1'));
console.log('');
console.log('  Found ' + allVars.size + ' env var(s): ' + secrets.length + ' sensitive, ' + configs.length + ' config');
console.log('  Platform detected: ' + (hasVercel ? 'Vercel' : hasRailway ? 'Railway' : hasFly ? 'Fly.io' : 'unknown'));
console.log('  Suggested vault: ' + W(vault, '36;1'));
console.log('');

if (secrets.length === 0) {
  console.log(W('  No sensitive env vars found.', '32'));
  console.log('  Add secrets to .env (locally) and migrate them using this command.');
  process.exit(0);
}

console.log(W('Sensitive vars to migrate:', '1'));
secrets.forEach(v => console.log('  • ' + v.key + ' (from ' + v.source + ')'));
console.log('');

// Output data for Claude to generate migration steps
console.log(JSON.stringify({ vault, secrets: secrets.map(v => v.key), configs: configs.map(v => v.key), platform: hasVercel ? 'vercel' : hasRailway ? 'railway' : hasFly ? 'fly' : null }, null, 2));
" -- "$1"
```

Using the JSON above, generate a step-by-step migration guide for the specified vault. Include:

**For Doppler:**
1. `brew install dopplerhq/cli/doppler && doppler login`
2. `doppler setup` (link to project)
3. For each secret: `doppler secrets set KEY value`
4. Update package.json scripts: prefix commands with `doppler run --`
5. For CI: `doppler secrets download --no-file --format env` in the workflow
6. Add `doppler.yaml` to .gitignore, remove `.env` files

**For Infisical:**
1. `npm install -g @infisical/cli && infisical login`
2. `infisical init`
3. Import secrets: `infisical secrets set KEY=value`
4. Run with: `infisical run -- node server.js`
5. GitHub Actions integration snippet

**For Vercel:**
1. `vercel env add SECRET_NAME` for each secret
2. Environment selection (production/preview/development)
3. Pull to local: `vercel env pull .env.local`
4. Confirm: `vercel env ls`

**For Railway:**
1. `railway variables set KEY=VALUE` for each secret
2. Confirm: `railway variables`

End with:
- What to delete after migration (list the .env files to remove)
- How to verify nothing broke: `npm run dev` or equivalent
- How to share with teammates without sharing the actual secrets
