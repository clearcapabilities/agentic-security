---
description: Explain a security finding as a story, not jargon. "Meet Mallory. She visits your /api/users page, changes ?id=1 to ?id=2, and now she's reading your other users' data." Designed for non-technical builders to viscerally understand what they're shipping. Use after /scan when /explain feels too clinical.
argument-hint: "<finding-id> | --random | --worst"
---

# Story-mode explain

`/explain` gives you a clinical security explanation. This skill gives you a story. The goal is to make the bug FEEL real — to a builder who doesn't yet have intuition for what an attack actually looks like.

## What you do

Given a single finding from `.agentic-security/last-scan.json` (or pick one if no ID is given), produce a 4-act story:

1. **The setup** — a sentence introducing the application and where the bug lives
2. **The attacker** — name them ("Meet Mallory", "Meet Eve", "Meet Trent" — different names per finding, never always "Mallory")
3. **The attack, step by step** — concrete actions taken, in present tense. Each action is one line. The technical detail goes in **bold** so the builder can later find it again.
4. **The aftermath** — what specifically the attacker walks away with. Tied to money/users/regulatory impact.

End with a one-line "What stops this" — the literal code change.

## Tone rules

- **Present tense, third-person.** "Mallory opens", not "an attacker would open".
- **Specific, not abstract.** If the bug is in `GET /api/users/:id`, name that URL — don't say "an authentication endpoint".
- **Concrete values.** Show an actual payload like `?id=2` not `?id=<some-other-id>`.
- **Costs in $.** Tie consequences to money where possible: "Stripe charges $0.30 per fraudulent charge dispute. Mallory creates 4,000 fake disputes in an afternoon. $1,200 cost, plus dispute-rate penalty."
- **No "could" — say "does".** "Mallory does X." Past conditional is for legal disclaimers, not stories.
- **No security acronyms in the story body.** Save "IDOR / CWE-639 / OWASP A01" for the footer.

## Structure template

```
─── Story: <Vuln name> at <file>:<line> ─────────────────────────

Setup
  <2 sentences: what this app does, where the vulnerable code sits, what
  it's supposed to do.>

Meet <Name>
  <1 sentence describing the attacker's motivation. Bored teen / fraudster /
  competitor / disgruntled ex-customer / opportunist — pick the persona that
  best fits the bug class.>

The attack (12:47pm, Tuesday)
  1. <Name> opens https://yourapp.com/<endpoint>
  2. <Name> notices <observable thing>
  3. <Name> changes <specific payload> from `<original>` to `<malicious>`
  4. The server returns <specific bad outcome>
  5. <Name> writes a 10-line script that does this 50,000 times overnight
  6. By morning, <name> has <specific stolen artifact>

The aftermath (Wednesday morning, 9:14am)
  - <First customer support ticket>
  - <First media post>
  - <Regulatory notification clock starts: GDPR 72h>
  - <Estimated cost: $X based on data class and customer count>

What stops this
  <The specific code change — 2-3 lines max. Show before/after if it fits.>

─── /story-explain ──────────────────────────────────────────────
  CWE: <X>   |   OWASP: <Y>   |   Severity: <Z>
  Run /fix --one <id> to apply the fix.
```

## How to apply this command

1. Read `.agentic-security/last-scan.json`.
2. If `${1}` is a finding ID, pick that finding. If `--worst`, pick the highest-severity. If `--random` or empty, pick a random high/critical finding.
3. Read ±40 lines of context around `file:line` so you have specifics to weave in.
4. Read the finding's CWE/vuln to pick the right attack archetype:

| Vuln class | Attacker persona | Story arc |
|---|---|---|
| SQL Injection | competitor doing recon | finds login → injects → dumps all users → posts on a leak site |
| IDOR | curious user, then a fraudster | changes ID in URL → reads other users → builds a scraper → uploads to a leak site |
| XSS (stored) | griefer, then a phisher | posts script → script logs every viewer's session → uses tokens to action-on-behalf-of |
| Open Redirect | phisher | sends victim to real domain → real domain redirects to fake login → captures credentials |
| Hardcoded API key | bot scraping github | bot finds key in minutes → uses key until rate limit hit → racks up bill |
| Prompt Injection | researcher, then a competitor | submits payload via review/PDF → agent leaks system prompt → leaks user data |
| Missing rate limit | scaling bug, then abuse | one buggy client → 50k req/min → no one else can use the app |
| Path Traversal | attacker hunting secrets | reads `../../../.env` → finds AWS keys → cloud spend spike |
| SSRF | researcher | hits 169.254.169.254 → IAM creds → spins up GPU instances |
| Service-role on client | curious user | inspects bundle → finds key → has admin DB access from a browser tab |

5. Produce the story following the template, customized to the actual file/route/vuln.
6. Keep total length under ~25 lines. Make every line earn its place.

## Don't

- Don't use generic boilerplate. Every story should mention this specific file, this specific function, this specific endpoint.
- Don't moralize. The reader knows it's bad. Show why, don't lecture.
- Don't make the attacker mustache-twirling. The most realistic attackers are bots and bored teenagers.
- Don't end on a cliffhanger. End with the fix.

🛡  agentic-security · created by Clear Capabilities
