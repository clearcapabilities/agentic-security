---
description: List every agentic-security command organized by category, with one-line descriptions and example invocations.
---

Print the full agentic-security command catalog.

```
agentic-security commands

EASY MODE — three commands. The whole product.
  /scan --all                One-screen "safe to deploy?" verdict
  /show-findings             Triage FPs then open interactive HTML report
  /fix --all                 Batch-fix every finding at or above --severity

DEVELOPER MODE — full catalog below.

SCANNING
  /scan --all                Full SAST + SCA + secrets sweep (one-screen verdict)
  /scan --sca-only           Dependency CVE audit only (OSV.dev-backed)
  /scan --secrets-only       Hardcoded credential / API key scan only
  /scan --authz              Deep auth/authZ audit — JWT, OAuth2, IDOR, session fixation
  /scan --mcp                Audit MCP server configs for agent-host risks
  /scan --pipeline           Audit GitHub Actions; --format pbom for Pipeline BOM
  /scan --logic              Semantic business-logic review (intent vs. implementation)
  /scan --diff               Score git diff by architectural risk (--since <ref>)

VIEWING & ANALYSIS
  /show-findings             Triage FPs then open interactive HTML report
  /show-findings --kev       Show only CISA KEV (actively weaponized) findings
  /show-findings --chains    Synthesize multi-finding exploit chains
  /show-findings --threat-model  STRIDE table (add --llm for OWASP LLM Top 10)

FIXING
  /fix --one <id>            Patch a single finding via the fixer subagent
  /fix --all [--critical|--high|--medium|--low]  Batch-fix by severity tier
  /fix --pr [--apply]        Bundle fixes into a feature branch + PR

DEEP ANALYSIS
  /security-poc              Generate adversarial PoC for a specific finding
  /security-explain          Plain-English explanation of any finding
  /security-launch-check     Pre-deploy 10-item checklist

POSTURE MANAGEMENT
  /security-drift            Compare two scans (--from a.json --to b.json)
  /security-sbom             CycloneDX 1.6 or SPDX 2.3 software bill of materials
  /security-aibom            AI/ML Bill of Materials — models, prompts, frameworks
  /security-api-inventory    Export full API surface map (md/json/openapi)
  /security-license          Enforce license allow/deny policy on deps
  /security-mttr             Show findings older than per-severity SLA

COMPLIANCE ATTESTATION
  /produce-compliance-report [nist|asvs|pci|soc2]  Auditor-ready attestation for any framework

PROJECT META
  /security-setup            Install short-form commands in this project
  /security-status           Plugin & project health snapshot
  /security-help             This command
  /security-grade            Letter grade (A–F) + README badge snippet
  /security-share            Posts (Twitter/LinkedIn/Discord/recap) about your security progress

USAGE NOTES
  - Every command works as /agentic-security:<name> too (the long form).
  - Most commands accept a [path] argument to limit scope.
  - First run /scan once. Most other commands read its output
    from .agentic-security/last-scan.json.
  - PostToolUse hook scans every Edit/Write automatically. Throttled per-file
    to one scan / 5s.
  - Set AGENTIC_SECURITY_OFFLINE=1 to skip all outbound calls (OSV, EPSS, KEV).

WHERE THINGS LIVE
  Project state:  .agentic-security/last-scan.json, rules.yml, license-policy.yml
  CVE cache:      ~/.claude/agentic-security/osv-cache/  (24h–7d TTL)
  Plugin bundle:  ~/.claude/plugins/cache/clearcapabilities/agentic-security/
```

Print the entire block above verbatim. The user wants the full catalog as a single screen, not a follow-up question. Do not summarize.
