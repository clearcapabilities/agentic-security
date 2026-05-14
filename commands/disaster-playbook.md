---
description: Generate a stack-specific incident response playbook BEFORE you get hacked. Detects Supabase / Stripe / Vercel / Auth0 / Clerk / AWS / npm in your project and writes a DISASTER.md with the exact commands and URLs you'll need to rotate creds, take backups, save logs, and recover — so when something bad happens you're not panic-Googling.
argument-hint: "[--output PATH] [--stack supabase,stripe,vercel,...]"
---

# Disaster recovery playbook

When you get hacked, you have one bad day. The thing that decides whether it's a bad day or a bad week is whether you already know:

- Where the "rotate this key" button is for every provider
- The exact SQL to snapshot your DB before doing anything reversible
- The exact CLI to pause your app while you investigate
- What `git filter-repo` syntax scrubs a leaked secret from history

This command writes all of that out into a single bookmarkable `DISASTER.md`, customized for your actual stack.

## What it generates

A markdown file with sections like:

- **The first 10 minutes — universal triage** (stop the bleeding / rotate / snapshot / save logs)
- **Supabase incident response** (service-role rotation, RLS audit, PITR, force re-auth)
- **Stripe incident response** (roll keys, audit charges, dispute fraud, Radar rules)
- **Vercel incident response** (rollback, paused auto-deploys, function-budget triage)
- **Auth0 / Clerk** (revoke sessions, rotate client secrets, re-auth)
- **AWS** (disable IAM key, hunt for crypto-mining instances, lock S3)
- **npm supply-chain** (pin out bad package, audit install scripts, rotate creds the script could read)
- **After the immediate fire is out** (disclosure, postmortem, regression tests)

Each section uses your actual env var names where possible (e.g., `SUPABASE_SERVICE_ROLE_KEY` not `<your-key>`).

## Usage

```bash
# Auto-detect stack, write DISASTER.md in the repo root
/disaster-playbook

# Custom output path
/disaster-playbook --output docs/incident-response.md

# Force a specific stack (skip detection)
/disaster-playbook --stack supabase,stripe,vercel
```

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/disaster-playbook.py ${ARGS}
```

After it runs, tell the user:
*"DISASTER.md is now in your repo. Star it. Re-run this command whenever you add a new platform — generated content goes stale fast."*

## Detection signals

| Stack | What triggers inclusion |
|---|---|
| Supabase | `supabase/config.toml` or `@supabase/*` in deps or `SUPABASE_*` in `.env*` |
| Stripe | `stripe` package or `STRIPE_*` in env |
| Vercel | `vercel.json` or `.vercel/` directory |
| Fly | `fly.toml` |
| Auth0 | `@auth0/*` package or `AUTH0_*` in env |
| Clerk | `@clerk/*` package or `CLERK_*` in env |
| AWS | `aws-sdk` / `@aws-sdk/*` or `AWS_*` in env |
| npm | any `package.json` (npm supply-chain advice applies universally) |

🛡  agentic-security · created by Clear Capabilities
