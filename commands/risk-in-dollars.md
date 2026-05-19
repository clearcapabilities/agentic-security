---
description: Translate every scanner finding into $ exposure (best-/likely-/worst-case). Replaces CVSS jargon with the language non-technical builders actually care about — money. Sources: public incident settlements + provider billing data.
argument-hint: "[--top N] [--json]"
---

# Risk in dollars

CVSS 7.4 doesn't motivate anybody. "$5M worst case if this fires" motivates everybody.

This command reads your scan output, maps each finding's CWE to a published-incident-derived $ exposure band, and shows them sorted by worst-case dollars. Every line also names the specific regulatory framework whose fines might apply.

## Output

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Security findings translated to $ exposure                                 │
└─────────────────────────────────────────────────────────────────────────────┘

  Total findings:       12
  Likely-case total:    $480k
  Worst-case total:     $32M

  #   $ WORST   $ LIKELY  CLASS                        FILE:LINE
  --- --------- --------- ---------------------------- -----------------------------------
  1   $50M      $60k      SSRF                         src/api/proxy.js:42
  2   $10M      $200k     Authentication Bypass        src/middleware/auth.js:17
  3   $5M       $80k      Hardcoded Credential         lib/aws-client.ts:8
  ...

Top-exposure finding:
  SSRF  (src/api/proxy.js:42)
  Scenario:    SSRF to cloud metadata = stolen IAM credentials = uncapped cloud spend.
               Capital One: $190M settlement (2019 SSRF → metadata → 100M records).
  Regulatory:  GLBA if financial data, GDPR/CCPA for PII
```

## Coverage

Currently maps 19 CWE classes to $ bands with named scenarios + specific regulatory triggers:

- Injection family: SQLi, command injection, code injection, path traversal, SSRF, XXE
- Auth/authz family: missing authz, IDOR, JWT bypass, mass assignment, signature missing
- Client-side family: XSS, CSRF, open redirect
- Supply chain: hardcoded credentials, insecure deserialization
- LLM family: prompt injection, insecure LLM output, unbounded LLM consumption

Anything not covered falls back to a conservative default band.

## Usage

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
/risk-in-dollars              # full table
/risk-in-dollars --top 5      # top 5 by worst-case
/risk-in-dollars --json       # machine-readable for board decks
```

## Honest disclaimers

- These are **conservative estimates from public-data**, not legal advice.
- Real-world cost depends heavily on data class, customer base, jurisdiction, insurance coverage, and how the breach gets handled.
- Treat as a **prioritisation tool**, not a forecast.
- The numbers are designed to be defensible — they err low for likely-case and reference real settled-case worst-cases.

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/risk-in-dollars.py ${ARGS}
```

After showing the table, suggest:
*"Want to fix the top-exposure finding now? Run `/fix --one <id>` or `/find-and-fix-everything` to handle all of them. To re-run after fixes, just call `/risk-in-dollars` again."*

🛡  agentic-security · created by Clear Capabilities
