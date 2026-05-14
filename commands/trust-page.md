---
description: Generate /.well-known/security.txt + /security page that shows your LIVE posture (critical/high counts, clean-scan streak, last scan time). Buyers and infosec teams look for these. Most vibe-coded apps have neither. Auto-detects Next.js App Router / Pages Router / vanilla and writes the right file shape.
argument-hint: "--contact <email> [--pgp <url>] [--canonical-url https://yourapp.com]"
---

# Trust page + security.txt

When an enterprise security team is evaluating you, the first thing they check is `<yourdomain>/.well-known/security.txt`. The second thing is `<yourdomain>/security`. If both exist and look professional, you pass a silent gate most vibe-coded apps fail.

## What it generates

1. **`public/.well-known/security.txt`** — RFC 9116-compliant contact file with `Contact:`, `Expires:` (1 year), `Preferred-Languages:`, optional `Encryption:` (PGP key URL), and `Canonical:`.
2. **`public/security-posture.json`** — live snapshot of your scan posture, read by the page below at build time.
3. **`/security` page** — framework-detected:
   - Next.js App Router → `app/security/page.tsx`
   - Next.js Pages Router → `src/pages/security.tsx`
   - Anything else → `public/security/index.html`

The page shows: traffic-light state (Green/Yellow/Red), critical/high/medium counts, clean-streak days, last-scan time, the practices block, and the disclosure contact.

## Usage

```bash
/trust-page --contact security@myapp.com
/trust-page --contact security@myapp.com --pgp https://keys.openpgp.org/abc.asc --canonical-url https://myapp.com
```

## What appears in security.txt

```
Contact: mailto:security@myapp.com
Expires: 2027-05-14T12:51:23.000Z
Preferred-Languages: en
Encryption: https://keys.openpgp.org/abc.asc
Canonical: https://myapp.com/.well-known/security.txt
Policy: https://myapp.com/security
```

Expires is auto-set to one year from generation — re-run periodically so it never expires.

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/trust-page.py ${ARGS}
```

After it runs, suggest:
*"Two more things to make this complete:*
- *Run `/security-onepager` for the sales-deliverable counterpart.*
- *Run `/privacy-docs` if you haven't already — link both PRIVACY.md and security.txt from the new /security page."*

## Honest principle

The page shows actual numbers. If your scan has 5 critical findings, the page says so. The point is not to fake a green light — it's to demonstrate that you have a measurable security posture and a working contact channel. Buyers value honesty over zeros.

🛡  agentic-security · created by Clear Capabilities
