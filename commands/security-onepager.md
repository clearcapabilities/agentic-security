---
description: Generate a customer-facing 'How we keep your data safe' one-pager from your ACTUAL scan posture. Hand it to enterprise prospects who ask 'are you secure?'. Distinct from /security-badge — this is the full artifact ready for sales emails, security questionnaires, and trust pages.
argument-hint: "[--output PATH] [--company NAME] [--contact EMAIL]"
---

# Security one-pager

Buyers ask "are you secure?" If your answer is "uh, I think so" you lose the deal. If your answer is "here's our one-pager — generated from our live security tooling — and our `/.well-known/security.txt` confirms the contact," you win the deal.

## What it generates

A markdown document with:

1. **Posture summary** — live counts of critical/high/medium findings, clean-scan streak days
2. **Stack** — detected from your `package.json`, `vercel.json`, etc.
3. **What we actually do** — auto-derived from your scan output and stack:
   - Continuous static analysis (always — if you have this plugin)
   - Dependency monitoring (OSV + KEV)
   - Supply-chain auditing (if scan results show supply-chain checks ran)
   - Authorization auditing (if authz rules ran)
   - Row-level security review (if Supabase detected)
   - Webhook integrity (if Stripe detected)
   - Hardened HTTP headers (if `/harden` has been applied)
4. **Data handling** — TLS, encryption-at-rest, least-access, retention boilerplate
5. **Incident response** — your contact, 24h ack / 72h initial assessment / GDPR Art. 33 commitment
6. **Frameworks** — OWASP ASVS, LLM Top 10, NIST AI 600-1 alignment statement
7. **Footer** — links back to your live security.txt and re-generation invitation

Output is plain markdown — paste into Notion, convert to PDF with `pandoc`, or serve as a `/security` page.

## Usage

```bash
# Auto-detect company from cwd name
/security-onepager

# Override
/security-onepager --company "Acme Inc." --contact security@acme.com

# Custom output
/security-onepager --output docs/SECURITY.md
```

## Convert to PDF

```bash
pandoc SECURITY.md -o SECURITY.pdf --pdf-engine=xelatex
# Or:
markdown-pdf SECURITY.md
```

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security-onepager.py ${ARGS}
```

After generation, ask the user:
*"Want me to also generate the matching `/.well-known/security.txt` and `/security` page? Run `/trust-page`."*

## Honesty principles

This artifact is generated, not invented:

- If you have unresolved critical findings, the posture line says so. Don't ship a one-pager that claims "zero issues" when the scanner disagrees.
- The "what we do" section only includes practices the scan output actually evidences (Supabase RLS audit only appears if Supabase is in your deps, etc.).
- The frameworks line says "we operate in line with" — not "certified" — for any framework you don't have a real audit for.

🛡  agentic-security · created by Clear Capabilities
