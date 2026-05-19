# Positioning — what this tool is and isn't, by ICP

Premortem item #15 surfaced the failure mode of trying to serve two ICPs with
one feature surface. The 77 slash commands today break roughly into:

| Lane         | Examples                                                                                                  | What it sells |
|--------------|-----------------------------------------------------------------------------------------------------------|---------------|
| **Vibecoder**| `/scan`, `/fix`, `/secure`, `/report-card`, `/risk-in-dollars`, `/tutorial`, `/destructive-guard`, `/harden` | "Don't ship something I'll regret" |
| **Pro**      | `/security-scan-all`, `/security-poc-generator`, `/compliance-report`, `/three-agent-review`, `/llm-redteam`, `/ultrareview` | "Replace one of my AppSec sub-processes" |
| **Both**     | `/install-hooks`, `/ci-gate`, `/ci-gate-multi`, `/show-findings`, `/triage`, `/explain`                  | Either ICP gets value from these |

## The premortem failure mode

Six months out, the team is being asked at the same meeting both:

- "Why doesn't this just stop my next mistake?" (vibecoder)
- "What's your held-out F1?" (pro/enterprise security buyer)

Today, every roadmap item makes one of these louder than the other. Without an
explicit positioning call, the team will keep building both and convince
neither.

## The choice (today)

**Primary ICP: vibecoder.** Decisive signals:

1. Default install path optimizes for "type one slash command and get a
   verdict" — that's the vibecoder flow.
2. Outputs are deliberately non-jargon: `/report-card`, `/risk-in-dollars`,
   `/launch-check`, `/disaster-playbook`.
3. The bodyguard / destructive-guard / fix-history surface is the unique moat
   — pro tools have F1, but they don't intercept LLM tool calls at write time.

**Pro is a follow-on, not a co-equal.** The pro features that already shipped
(taint catalog, calibrated CI, MCP server, three-agent review) stay, but
roadmap **net-new** work goes to vibecoder unless the pro feature unlocks
something the vibecoder also needs.

## What this rules in / out

- IN for next two quarters: every detector class that maps to "stuff a
  vibecoder ships and regrets" (Supabase RLS, NEXT_PUBLIC_ leaks, Stripe
  webhook signatures, LLM-cost ceilings, dangerouslySetInnerHTML, JWT-no-verify).
- IN: a sharper, smaller default scan that gives a verdict in <10s on a
  median project.
- OUT: more compliance frameworks beyond the three already shipped. Each
  added framework expands the auditor-grade defensibility burden without
  moving vibecoder retention.
- OUT: more bench corpora beyond the CVE-replay seed corpus. Pick one
  corpus, drive it to 500 entries, publish a calibrated number against it.
- OUT: more languages beyond JS/TS/Python until those two clear F1 ≥ 0.85
  on the CVE-replay corpus.

## What each ICP gets to hear

- **Vibecoder:** "We catch the bug at write time. The first time you ship
  is the time it matters."
- **Pro:** "We give you a hash-chained audit log, a held-out F1 against a
  growing CVE corpus, and an MCP server your agent fleet can call."

The two messages don't contradict. But the **center of gravity** of the
product — what gets built next, what gets prioritized in the help text, what
the README opens with — is the vibecoder.

## Review cadence

Revisit this doc at every minor release. If the held-out F1 on the
CVE-replay corpus passes 0.85 with n ≥ 100, that's the trigger to consider
re-balancing — because at that point the pro pitch has a defensible number
the vibecoder pitch doesn't need.
