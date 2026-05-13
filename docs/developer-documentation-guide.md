# AGENTIC-SECURITY

```
NAME
       agentic-security — local-first SAST + SCA + secrets + IaC + LLMSecOps
       scanner with audit-grade suppressions, machine-readable output, and
       integrations for the security stack you already run.

VERSION
       0.32.0

SYNOPSIS
       agentic-security [--profile pro] COMMAND [ARGS] [OPTIONS]

       Claude Code slash commands (preferred interface):

       Core scanning & fixing:
       /scan [PATH] [--all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff]
       /fix [--one <id>] [--all [--severity]] [--pr [--apply]]
       /show-findings [--all|--kev|--chains|--threat-model]
       /validate-findings <finding-id>
       /explain <finding-id|CWE-N|vuln-name>

       Vibe-coder essentials (0.32.0):
       /stack-playbook
       /harden
       /db-audit
       /auth-audit
       /rate-limit-check
       /webhook-audit
       /env-check
       /rotate-secret [secret-value-or-finding-id]
       /deploy-check
       /attack-surface
       /prompt-firewall
       /csp-cors
       /security-tests [--finding <id>|--all|--critical]
       /ci-gate [--severity critical|high|medium] [--comment] [--apply]
       /cve-alerts [--slack <url>|--discord <url>] [--apply]
       /vault-wizard [doppler|infisical|vercel|railway]
       /security-trend
       /security-badge

       Dependency & supply chain:
       /trim-dependencies [path] [--dry-run] [--include-dev]
       /dep-freshness
       /dep-pinning
       /dep-alternatives
       /install-script-audit
       /vendor-audit

       Posture & compliance:
       /posture-management [--sbom|--aibom|--api|--license|--drift|--mttr]
       /compliance-report [nist|asvs|pci|soc2|llm]
       /status
       /report-card
       /launch-check
       /social-media
       /help

DESCRIPTION
       agentic-security is a Claude Code plugin and standalone CLI for catching
       the security defects that AI-assisted development introduces and the
       traditional ones the AI inherits from training data. It runs locally
       (no cloud, no signup), emits SARIF + JSON + CSV every scan, and
       supports the workflow security engineers actually use: triage state,
       audit-grade suppressions, org-wide fleet scans, and custom rules.

       F1 benchmark: 100% precision and recall on 33/33 real-world and
       adversarial benchmarks (OWASP Benchmark, NodeGoat, Juice Shop, DVWA,
       LLMGoat, AIGoat, and more). Zero false positives on baseline fixtures.

       Coverage pillars:

         SAST        Taint analysis (regex + AST) for JS/TS, Java, Python.
                     25+ language-specific modules: SQL injection, XSS, command
                     injection, XXE, JNDI (Log4Shell), Java deserialization,
                     zip-slip, JWT flaws, auth provider misconfig (Clerk,
                     NextAuth, Auth0, Lucia), Supabase RLS audit, rate-limit
                     gaps, env hygiene, webhook signature verification, React
                     client-side XSS/localStorage, C/C++, C#, Go, Rust,
                     Solidity smart contracts, LLM prompt firewall.
         SCA         OSV + CISA KEV + EPSS, function-level reachability,
                     dep confusion, typosquat detection, deprecated packages
                     (npm, PyPI, Packagist, crates.io, RubyGems, pub.dev).
         Secrets     60+ credential patterns, high-entropy heuristic,
                     allowlist-aware, provider-specific rotation guidance.
         IaC         Dockerfile, docker-compose, GitHub Actions, Kubernetes.
         Deploy      Vercel, Railway, Fly.io, Netlify, Cloudflare Workers —
                     security headers, HTTPS enforcement, preview deployments,
                     health checks, compat dates.
         LLM         OWASP LLM Top 10 (2025) + prompt firewall (system prompt
                     contamination, missing max_tokens, LLM output→SQL/exec,
                     output schema validation).
         MCP         Agent-tool audit for over-privileged MCP servers.
         Pipeline    GitHub Actions: floating tags, secret echoes,
                     OIDC misconfig, write-all permissions.
         Auth/AuthZ  Broken access control, IDOR, mass assignment,
                     session fixation, JWT confusion, OAuth2 PKCE, Clerk/
                     NextAuth misconfig, dangerous email account linking.
         Container   Base-image EOL, exposed ports, runtime mode.
         Compliance  NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2,
                     OWASP LLM Top 10 (2025).
         Stack       Opinionated security playbook for Next.js, Supabase,
                     Stripe, Clerk, NextAuth, Prisma, Drizzle, OpenAI,
                     Anthropic, LangChain, MongoDB, Firebase, tRPC, FastAPI,
                     Django, and more.
         Trend       Rolling scan-history snapshots, fixed/introduced delta,
                     sparkline view, regression detection.
```

---

## SETUP

```
       agentic-security profile set pro
```

Flips the defaults: full taxonomy visible (CWE/CVSS/OWASP/MITRE/CAPEC),
confidence threshold lowered (≥0.3 vs. ≥0.9 in vibecoder mode), all
commands and flags accessible, SARIF + CSV written on every scan,
suppression schema upgraded to audit-grade.

Confirm with:

```
       agentic-security profile show
```

---

## COMMANDS

### Core scanning & fixing

```
       scan [PATH]
              Full SAST + SCA + secrets + IaC sweep. PATH defaults to cwd.
              Writes findings.{json,sarif,csv} to .agentic-security/.
              Also appends a snapshot to scan-history.json for /security-trend.

       fix --one <id>
              Emit the canonical patch template for one finding. The
              security-fixer subagent applies it to the affected file with
              full codebase context — detects auth library, ORM, and
              framework before writing the fix.

       fix --all [--critical|--high|--medium|--low]
              Batch-fix every finding at or above the severity tier.
              Cumulative: --high fixes critical + high. Default: --critical.

       fix --pr [--apply] [--branch <name>] [--severity critical|high|all]
              Bundle fixes into a feature branch and open a pull request.
              Default is dry-run; pass --apply to commit changes.

       triage list | assign | transition | trend
              Per-finding state machine. List by status, severity, or
              assignee. Trends compute MTTR + opened/closed deltas.

       org-scan --repos <list> [--workers N]
              Fleet scan. Workspace-aware (Nx, Turborepo, pnpm).
              Per-repo + rolled-up JSON output.

       rules validate
              Lint .agentic-security/rules.yml for schema errors, invalid
              regex, severity overrides, and disabled rules.
```

### Vibe-coder essentials (added in 0.31.0–0.32.0)

```
       stack-playbook
              Detect the project's tech stack from package.json /
              requirements.txt and output an opinionated, copy-paste-ready
              security checklist for the specific combination of frameworks
              in use. Supports: Next.js, Supabase, Stripe, Clerk, NextAuth,
              Prisma, Drizzle, OpenAI, Anthropic, LangChain, MongoDB,
              Firebase, tRPC, FastAPI, Django, and email providers.

       harden
              One-command security hardening. Applies 7 safe automated
              changes to the project:
                1. .env* entries added to .gitignore
                2. Security headers injected into next.config.js
                3. npm audit script added to package.json
                4. .env.example created from .env with placeholders
                5. Security disclosure section added to README
                6. SECURITY.md created
                7. *.pem / *.key / serviceAccountKey.json added to .gitignore
              Prints applied/skipped/failed per step. Safe to run multiple
              times (idempotent per item).

       db-audit
              Surfaces all database security findings from last-scan.json:
              Supabase service-role key exposure, NEXT_PUBLIC_ vars leaking
              service keys, auth.admin called client-side, bypassRowLevel-
              Security() in query chains, SQL tables without RLS enabled,
              raw pg Pool/Client in request handlers, and SQL injection.
              Provides remediation steps and severity breakdown.

       auth-audit
              Deep-audits the authentication layer. Covers: allowDangerous-
              EmailAccountLinking, trustHost: true (CSRF bypass), missing
              NEXTAUTH_SECRET, weak or hardcoded session secrets, hardcoded
              OAuth clientSecret, CSRF protection disabled, Clerk sensitive
              paths in publicRoutes, session cookies without secure/sameSite,
              JWT alg:none, algorithm confusion, JWT without expiry.

       rate-limit-check
              Find API endpoints missing rate limiting by category:
                auth    — login/register/forgot/verify (brute-force risk)
                ai      — generation/chat/inference (cost explosion risk)
                payment — stripe/checkout/pay (card-testing risk)
                contact — forms/newsletter/waitlist (spam risk)
              Prints copy-paste @upstash/ratelimit setup for serverless
              and express-rate-limit for Node servers.

       webhook-audit
              Audit webhook handlers for missing cryptographic signature
              verification. Detects provider (Stripe, GitHub, Clerk, Svix,
              Resend, Twilio) from imports and URL patterns. Fires only when
              ALL signals are present: webhook path + body read + no verify.
              Explains the fake-payment attack vector and provides provider-
              specific fix snippets including raw-body parser requirements.

       env-check
              Runtime + scan-based environment hygiene report:
                • .env* files absent from .gitignore
                • .env* files tracked in git (git ls-files check)
                • NEXT_PUBLIC_*SECRET/KEY/TOKEN vars in env files
                • .env.example / .env.sample with real-looking values
                • process.env.X || "real-fallback" in source code
                • dotenv loaded in non-entry files

       rotate-secret [value]
              Given a secret value or finding ID, detects the provider
              (OpenAI, Anthropic, Stripe, GitHub, AWS, Supabase, Slack,
              SendGrid, Resend, Twilio) from the key prefix/pattern. Lists
              every file referencing the secret. Provides platform-specific
              rotation steps (Vercel / Railway / Fly / Render / Netlify).
              Ends with post-rotation verification checklist and git-history
              purge advice.

       deploy-check
              Platform-specific infra security audit. Detects platform from
              config files and checks:
                Vercel   — security headers in vercel.json / next.config.js,
                           public preview deployments
                Railway  — health check configuration
                Fly.io   — force_https, auto_stop_machines
                Netlify  — security headers in netlify.toml
                Cloudflare Workers — compatibility_date in wrangler.toml
              Provides copy-paste remediation for each platform.

       attack-surface
              Gathers scan statistics (severity counts, KEV deps, attack
              chains, unauth state routes) and instructs Claude to synthesise
              a plain-English threat narrative — 3–5 realistic attack
              scenarios with attacker steps, impact, likelihood, and
              single-line fix per scenario. Written for builders, not
              security engineers.

       prompt-firewall
              Surfaces all LLM/AI security findings:
                • User input concatenated into system prompts (prompt
                  injection via system prompt contamination)
                • Missing max_tokens cap (cost explosion / DoS)
                • LLM output used as SQL/shell/eval input (second-order
                  injection — critical severity)
                • LLM response consumed without schema validation
              Gate: all rules require an LLM API import to fire (zero
              impact on non-AI codebases).

       csp-cors
              Reads package.json for external services (Supabase, Stripe,
              Clerk, OpenAI, analytics, Sentry, Intercom) and instructs
              Claude to generate exact Content-Security-Policy and CORS
              config for the detected framework and deployment platform.
              Outputs ready-to-paste header blocks for Next.js, Express,
              and Vercel JSON.

       security-tests [--finding <id>|--all|--critical]
              Detects the project's test framework (Vitest, Jest, pytest,
              Node test runner) and instructs Claude to generate per-finding
              test files with:
                • A failing test proving the vulnerability is exploitable
                • A passing test proving the fix works
              Uses real imports from the affected file, not mocks. Outputs
              as security/<slug>-security.test.{js|ts|py}.

       ci-gate [--severity critical|high|medium] [--comment] [--apply]
              Generates .github/workflows/security.yml that:
                • Runs on pull_request and push to main
                • Uploads SARIF to GitHub Security tab
                • Posts a PR review comment with finding counts and
                  top findings (with --comment)
                • Fails the build on findings at --severity threshold
              Default threshold: high. Pass --apply to write the file.

       cve-alerts [--slack <url>|--discord <url>] [--apply]
              Generates:
                • scripts/cve-monitor.mjs — checks OSV for new CVEs
                  across all installed packages, tracks seen IDs in
                  .agentic-security/cve-alert-state.json, posts to
                  Slack/Discord webhook when new CVEs drop
                • .github/workflows/cve-alerts.yml — daily 8am UTC cron
              Pass --apply to write the files. Set CVE_ALERT_URL secret
              in GitHub Actions for notifications.

       vault-wizard [doppler|infisical|vercel|railway]
              Inventories all env vars across .env*, classifies them as
              sensitive (SECRET/KEY/TOKEN/PASSWORD patterns) vs. config,
              and instructs Claude to generate a step-by-step migration
              guide to the specified vault including CLI commands, CI
              integration snippets, and post-migration cleanup instructions.
              Auto-detects platform if target not specified.

       security-trend
              Reads .agentic-security/scan-history.json (appended by every
              scan) and renders:
                • Bar-chart sparkline of total findings over time
                • Fixed vs. introduced delta between last two scans
                • Net change with colour coding (green=improving)
                • List of newly introduced finding IDs
              Each /scan --all run automatically appends a snapshot.

       security-badge
              Computes letter grade (A–F) from last-scan.json and generates:
                • Shields.io badge Markdown for README
                • Professional security posture paragraph for investor
                  due-diligence questionnaires or pitch decks
                • SOC 2 evidence note mapping to CC6.1, CC6.6, CC7.1, CC7.2
```

### Dependency & supply chain

```
       trim-dependencies [PATH] [--dry-run] [--include-dev]
              Find installed packages never imported in source code.
              Reports per-package on-disk size and transitive dep count.
              Default is --dry-run; pass --apply to execute removals.

       dep-freshness
              Score how stale direct dependencies are across all ecosystems.
              Stale deps are the primary CVE accumulation vector.

       dep-pinning
              Audit manifests for loose version ranges that allow silent
              supply-chain injection. Flags unpinned deps and missing
              lockfiles.

       dep-alternatives
              Find heavy or high-risk dependencies with lighter-weight,
              native, or more actively maintained alternatives.

       install-script-audit
              Audit every npm package (direct and transitive) for
              postinstall/preinstall scripts — the primary supply-chain
              attack vector in the npm ecosystem.

       vendor-audit
              Find copy-pasted or bundled third-party code vendored directly
              into the repo — invisible to dependency scanners and never
              receiving security updates.

       digest --slack <url> | --discord <url>
              POST a structured digest payload to a Slack/Discord webhook.

       profile show | set | detect
              Persona master switch. detect uses heuristic signals
              (SECURITY.md, CI workflow named *security*, etc.).

       packs list
              List available rule packs (owasp-top-10, cwe-top-25,
              llm-security, supply-chain).
```

---

## OPTIONS

```
       --format FORMAT
              Output: cli, json, md, sarif, csv, html, cyclonedx, spdx,
              pbom, aibom, aibom-md.

       --columns SET
              Pro-mode column profile for the cli renderer:
                standard  CWE + CVSS + OWASP
                mitre     ATT&CK technique + tactic
                capec     CAPEC attack-pattern number
                owasp     OWASP Top 10 category

       --confidence N
              Override the per-profile confidence threshold (0.0–1.0).

       --firehose
              Show ALL findings (ignore confidence threshold). Useful for
              audits, debugging, or feeding a downstream filter.

       --honest
              High-confidence-only view (≥0.9). Strict subset of
              --firehose.

       --severity {critical|high|medium|low|info}
              Exit-code threshold for CI gating.

       --only {sast|sca|secrets}
              Limit to one pillar.

       --sca-reachable-only
              Drop SCA findings where the vulnerable function is not
              reachable from any route handler.

       --ingest-sarif <glob>
              Merge external SARIF (gitleaks, Trivy, Checkov, Bandit)
              into this scan. Findings dedupe by fingerprint.

       --scorecard
              Enrich SCA components with OSSF Scorecard scores.

       --no-network
              Skip OSV / registry / EPSS / KEV queries (offline mode).

       --pack <name>[,<name>...]
              Focus on a CWE allowlist: owasp-top-10, cwe-top-25,
              llm-security, supply-chain. Multiple packs union their sets.

       --output FILE
              Write the rendered report to FILE.
```

---

## OUTPUT FILES

Every scan writes to `.agentic-security/` in the project root:

```
       findings.json    Normalized findings, programmable schema.
       findings.sarif   SARIF 2.1.0 for GitHub Security tab, GitLab, etc.
       findings.csv     Spreadsheet / BigQuery / executive reports.
       last-scan.json   Live state consumed by /fix, /show-findings,
                        /posture-management, /db-audit, /auth-audit,
                        /rate-limit-check, /webhook-audit, /attack-surface,
                        /prompt-firewall, /deploy-check, /security-badge,
                        /security-tests, /security-trend.
       scan-history.json  Rolling window (30 scans) for /security-trend.
                          Appended automatically on every scan.
       cve-alert-state.json  Seen CVE IDs for /cve-alerts deduplication.
       suppressions.yml Audit-grade suppression records.
       rules.yml        Custom rules, severity overrides, version pins.
       triage.json      Triage state machine.
       integrations.yml Webhooks + API tokens (gitignored).
       profile.yml      Persona profile (pro|vibecoder).
       streak.json      Security grade history and achievements.
```

---

## EXIT STATUS

```
       0   Clean — no findings at or above --severity
       1   Findings at low or medium severity
       2   Findings at high severity
       3   Findings at critical severity
       4   Engine error (parse failure, IO, malformed config)
```

CI gating example — blocks the pipeline on any critical finding:

```bash
       agentic-security scan . --severity critical
```

Or use the generated workflow from `/ci-gate --apply`.

---

## FINDINGS SCHEMA

Every finding produced by the scanner includes:

```json
{
  "id":          "module:RULE_ID:file/path.js:42",
  "title":       "Human-readable title",
  "vuln":        "Canonical vulnerability name (used for F1 family mapping)",
  "severity":    "critical | high | medium | low | info",
  "file":        "relative/path/to/file.js",
  "line":        42,
  "description": "What the vulnerability is and how it is exploited",
  "remediation": "Exact fix, often with code snippet",
  "cwe":         "CWE-89",
  "kev":         false,
  "toxicityScore": 0–100,
  "triageScore":   0–100
}
```

Severity values in order: `critical`, `high`, `medium`, `low`, `info`.

---

## SUPPRESSIONS

Suppressions are structured, reviewed, and auditable. Stored in
`.agentic-security/suppressions.yml`:

```yaml
       - finding_id: c14d...
         file: lib/admin.js
         line: 47
         cwe: CWE-798
         rule_version: 0.32.0
         reason: |
           Hardcoded credential is in a test fixture, not a production
           code path. Verified via call-graph analysis (no production
           caller).
         justification_signed_by: alice@team.example.com
         reviewer: bob@team.example.com
         reviewed_at: 2026-05-13T14:30:00Z
         expires_at: 2026-11-13T00:00:00Z
         ticket: SEC-1247
```

Validation rules:
- signer must differ from reviewer (two-person rule)
- expires_at must be in the future
- critical-severity findings cannot be suppressed without `--accept-critical`
- rule_version is pinned: a newer scanner re-surfaces the finding unless
  the suppression is re-approved

Lint with:

```
       agentic-security rules validate
```

Inline per-line suppression (source code):

```js
       const key = "hardcoded"; // agentic-security-ignore: hardcoded-secret
```

---

## TRIAGE

State machine: `open` → `in-progress` → (`fixed` | `wont-fix` | `false-positive`).
Findings auto-transition to `fixed` when the scanner no longer detects them.

```
       agentic-security triage list --status open --severity critical
       agentic-security triage assign SEC-0042 alice@team
       agentic-security triage transition SEC-0042 in-progress
       agentic-security triage transition SEC-0042 fixed \
              --comment "Patched in PR #94"
       agentic-security triage trend --since 30
```

`trend` output:

```
       Opened:  47
       Closed:  52
       Net:     -5 (improving)
       Open:    critical=2 high=8 medium=15 low=4
       MTTR median: 3.2 days
```

State is persisted to `.agentic-security/triage.json`.

---

## CUSTOM RULES

`.agentic-security/rules.yml`:

```yaml
       version: 0.32.0

       severityOverrides:
         "Hardcoded Credential Check": medium

       disable:
         - "Verify x-powered-by Header is Disabled"

       custom:
         - id: internal-auth-bypass
           regex: 'if\s*\(\s*request\.headers\[\s*[''"]x-internal-bypass[''"]'
           vuln: "Internal Auth Bypass Header"
           severity: critical
           cwe: CWE-287
           description: "x-internal-bypass is debug-only. Never in prod."
           fix: "Remove the x-internal-bypass header check."
```

---

## INTEGRATIONS

Configuration in `.agentic-security/integrations.yml` (gitignored).

```
       Jira / ServiceNow
              Body builders produce issue payloads; pipe to your
              existing client.

       GitHub Security tab / GitLab
              SARIF auto-written every scan. Upload via
              github/codeql-action/upload-sarif@v3.
              Use /ci-gate --apply to generate a full workflow.

       Slack / Discord
              Webhook digest with critical/high/medium counts +
              top 3 findings. Use /cve-alerts for daily CVE push alerts.

       SIEM (Splunk / Datadog / Elastic)
              One JSON event per finding, with source_attribution and
              rule_version for correlation.
```

---

## CI/CD

Auto-generated GitHub Actions workflow (recommended):

```
       /ci-gate --apply --severity high --comment
```

Manual CI runner (auto-detects PR base ref):

```bash
       npx @clearcapabilities/agentic-security-scanner ci . --fail-on critical
```

Raw scan with SARIF upload to GitHub Security tab:

```yaml
       - uses: actions/checkout@v4
       - uses: actions/setup-node@v4
         with: { node-version: '20' }
       - run: |
           npx @clearcapabilities/agentic-security-scanner scan . \
             --format sarif --output security.sarif
       - uses: github/codeql-action/upload-sarif@v3
         with: { sarif_file: security.sarif }
```

Pre-commit framework hook (`.pre-commit-config.yaml`):

```yaml
       - repo: https://github.com/clearcapabilities/agentic-security
         rev: v0.32.0
         hooks:
           - id: agentic-security
```

Runs `agentic-security ci --baseline HEAD --fail-on high` against
staged changes and blocks the commit on any high or critical finding.

Rule packs for focused scans:

```bash
       agentic-security scan --pack owasp-top-10 .
       agentic-security scan --pack cwe-top-25 .
       agentic-security scan --pack llm-security .
       agentic-security scan --pack supply-chain .
       agentic-security packs list
```

---

## ENVIRONMENT

```
       AGENTIC_SECURITY_OFFLINE=1
              Skip OSV / EPSS / KEV / Scorecard fetches.

       AGENTIC_SECURITY_SCORECARD=1
              Enable OSSF Scorecard enrichment (outbound API calls).

       AGENTIC_SECURITY_POC=1
              Demote findings the engine cannot generate a PoC for.

       DEBUG_BENCH_FILTER=1
              Verbose logging for the benchmark category filter.

       CVE_ALERT_URL
              Slack or Discord webhook URL for /cve-alerts monitor script.
```

---

## COMPLIANCE

Framework attestations (Claude Code slash commands):

```
       /compliance-report nist    NIST AI 600-1 (122 GenAI controls)
       /compliance-report asvs    OWASP ASVS Level 1+2
       /compliance-report pci     PCI-DSS 4.0
       /compliance-report soc2    SOC 2 Common Criteria CC6–CC9
       /compliance-report llm     OWASP LLM Top 10 (2025)
```

Bill of materials formats:

```bash
       agentic-security scan --format cyclonedx     # CycloneDX 1.6 SBOM
       agentic-security scan --format spdx          # SPDX 2.3
       agentic-security scan --format aibom         # CycloneDX 1.7 ML-BOM
       agentic-security scan --format pbom          # Pipeline BOM
```

Posture management artifacts:

```
       /posture-management --sbom           CycloneDX 1.6 or SPDX 2.3
       /posture-management --aibom          CycloneDX 1.7 ML-BOM (AI components)
       /posture-management --api            API surface map (md/json/openapi)
       /posture-management --license        License allow/deny policy enforcement
       /posture-management --drift          Diff two scan snapshots
       /posture-management --mttr           SLA breach report
```

---

## SEE ALSO

```
       commands/            Slash-command definitions for the Claude Code plugin.
       agents/              Sub-agent system-prompt definitions.
       scripts/             Compliance helper scripts (NIST, SOC 2, PCI-DSS,
                            OWASP ASVS, OWASP LLM Top 10).
       .claude-plugin/      Plugin manifest.
       CLAUDE.md            Codebase conventions and architecture.
       LICENSE              Full license terms.
```

---

## AUTHOR

Built by **[ClearCapabilities.Com](https://clearcapabilities.com)**.
Maintainer: Ross Young <ross@clearcapabilities.com>.

---

## BUGS

Report at <https://github.com/clearcapabilities/agentic-security/issues>.

---

# TUTORIAL

The following exercises walk through the tool from first scan to auditor-ready
compliance evidence. Work through them in order; each exercise builds on the
state left by the previous one.

---

## Exercise 1 — First scan

**Goal:** run a full scan, understand the output, and know what files were
written.

```
/scan --all
```

Or from the CLI:

```bash
agentic-security scan .
```

**What to look for:**

- The one-line verdict at the top: `SAFE TO DEPLOY` (green) or `NOT SAFE` (red).
- The severity breakdown: `critical=N high=N medium=N low=N`.
- The three output files written to `.agentic-security/`:
  - `findings.json` — full machine-readable results
  - `findings.sarif` — for GitHub / GitLab Security tabs
  - `findings.csv` — for spreadsheet or executive review
  - `scan-history.json` — automatically appended for `/security-trend`

**Checkpoint:** open `.agentic-security/findings.json` and confirm it has a
`findings` array. Note one finding ID — you'll use it in Exercise 3.

---

## Exercise 2 — Focused scans

Each pillar can be run independently.

**Dependency CVE audit only:**

```
/scan --sca
```

Backed by OSV.dev. Look for `kev: true` entries — these are on the CISA Known
Exploited Vulnerabilities catalog and should be treated as P0.

**Secrets sweep:**

```
/scan --secrets
```

Covers 60+ provider patterns (AWS, GCP, GitHub, Stripe, etc.) and high-entropy
heuristics. Any hit: rotate immediately with `/rotate-secret`, move to a secrets
manager with `/vault-wizard`, audit git history with `git log -S <value>`.

**Auth/AuthZ deep audit:**

```
/scan --authz
/auth-audit
```

The `--authz` flag covers JWT algorithm confusion, hardcoded JWT secrets, missing
`algorithms:[]`, OAuth2 PKCE, redirect_uri validation, session fixation, and
multi-tenant queries. `/auth-audit` surfaces provider-specific misconfigurations
(Clerk, NextAuth, Auth0, Lucia, Better Auth).

**Database security:**

```
/db-audit
```

Supabase-aware: RLS disabled, service-role key exposed client-side, admin API
in browser code, bypassed row-level security, raw pg connections in handlers.

**AI/LLM app security:**

```
/scan --logic
/prompt-firewall
```

`--logic` invokes the business-logic reviewer. `/prompt-firewall` surfaces
LLM-specific risks: system prompt contamination, missing max_tokens, model
output used as SQL/exec input (second-order injection), no output validation.

**MCP server audit:**

```
/scan --mcp
```

Reads `claude_desktop_config.json`, `.mcp.json`, `mcp_servers.json`. Flags
untrusted install vectors, hardcoded API keys, filesystem servers with broad
access, dangerous capability names.

**GitHub Actions pipeline audit:**

```
/scan --pipeline
```

Finds floating tags (`@latest`, `@main`), secret echoes, `write-all`
permissions, OIDC misconfigurations, `github.event.*` script injection.

**Platform infrastructure:**

```
/deploy-check
```

Checks your actual deployment config files: Vercel headers, Railway health
checks, Fly.io HTTPS, Netlify headers, Cloudflare Workers compat date.

**Diff review (before merging a branch):**

```
/scan --diff
/scan --diff --since main
```

Scores the git diff by architectural risk. Risk levels:
- `critical` — auth removed, new shell call → run `/validate-findings` + `/fix --one`
- `high` → run `/validate-findings`
- `medium`/`low`/`none` → safe to merge

---

## Exercise 3 — Understand a finding

Use the finding ID you noted in Exercise 1.

```
/explain <finding-id>
```

You can also explain by CWE or by name fragment:

```
/explain CWE-89
/explain SQL Injection
```

The output is a plain-English card with four sections:
1. What this means
2. How an attacker abuses it
3. Worst case if not fixed
4. How to fix it

**Advanced:** compare the plain-English explanation to the raw finding fields:

```bash
jq '.findings[] | select(.id == "<your-id>")' .agentic-security/findings.json
```

Fields to understand: `cwe`, `toxicityScore`, `kev`, `owaspCategory`.

---

## Exercise 4 — Validate a finding (optional)

Before applying a fix, confirm the finding is real.

```
/validate-findings <finding-id>
```

The PoC generator reads the affected file, constructs a concrete exploit payload,
and emits a Playwright regression test. If it cannot construct a payload it emits
`PROBABLE_FP` — use this to suppress false positives with justification.

---

## Exercise 5 — Apply fixes

Apply a fix to a single finding:

```
/fix --one <finding-id>
```

The security-fixer agent reads the affected file, its imports, the auth
middleware, the ORM/DB helpers it calls, and the route registration — then
applies the fix in the idiom of your specific stack (not a generic template).

Batch-fix all critical and high findings:

```
/fix --all --high
```

Bundle all fixes into a pull request (dry-run by default):

```
/fix --pr --severity high --apply
```

---

## Exercise 6 — Security trend

Run a second scan after applying fixes, then view the trend:

```
/scan --all
/security-trend
```

The trend view shows a sparkline bar chart, the number of findings introduced
vs. fixed, and a net delta. Green = improving, red = regressing.

---

## Exercise 7 — Harden the project

Apply safe automated infrastructure improvements:

```
/harden
```

Then review the changes:

```bash
git diff
```

The command prints what it applied, what it skipped (already configured), and
what failed. Review before committing.

---

## Exercise 8 — Stack-specific playbook

Get a checklist tailored to your exact stack:

```
/stack-playbook
```

For a Next.js + Supabase + Stripe app, this surfaces ~30 opinionated items
specific to how those three systems interact — not generic OWASP advice.

---

## Exercise 9 — Set up CI security gate

Generate and apply a GitHub Actions workflow:

```
/ci-gate --apply --severity high --comment
```

This creates `.github/workflows/security.yml`. Push it, open a PR, and the
scanner runs automatically — failing the build if critical/high findings are
introduced and posting a review comment with the summary.

---

## Exercise 10 — Generate compliance evidence

```
/compliance-report soc2
```

Outputs an auditor-ready mapping of scan findings to SOC 2 Common Criteria
controls (CC6.1, CC6.6, CC7.1, CC7.2, CC7.3). Use `/security-badge` to
generate the investor-ready paragraph and README badge.

---

## Exercise 11 — Set up CVE monitoring

```
/cve-alerts --slack https://hooks.slack.com/... --apply
```

Creates `scripts/cve-monitor.mjs` and `.github/workflows/cve-alerts.yml`.
Add `CVE_ALERT_URL` as a GitHub Actions secret, enable the workflow, and
your team gets notified at 8am UTC whenever a new CVE drops for any of your
installed packages.

---

## SAST MODULE REFERENCE

The scanner's SAST layer is composed of independently-loadable modules.
Each exports one or more `scan*()` functions returning `Finding[]`.

| Module | File | Key detections |
|--------|------|----------------|
| Core taint | `engine.js` | SQL injection, XSS, command injection, SSRF, path traversal, IDOR, mass assignment, prototype pollution, ReDoS, timing oracle |
| Auth/AuthZ | `sast/authz.js` | JWT alg:none, JWT hardcoded secret, missing algorithms, OAuth PKCE, redirect_uri allowlist, session fixation, multi-tenant scope |
| Auth provider | `sast/auth-provider.js` | Clerk/NextAuth/Auth0/Lucia misconfig: trustHost, allowDangerousEmailAccountLinking, missing NEXTAUTH_SECRET, weak secrets, CSRF disabled |
| Business logic | `sast/logic.js` | IDOR, state-machine bypasses, coupon abuse, race conditions |
| Client-side | `sast/client-side.js` | dangerouslySetInnerHTML w/o sanitizer, localStorage tokens, open redirect, postMessage no-origin, client eval |
| C/C++ | `sast/cpp.js` | Buffer overflow, strcpy/sprintf, integer overflow, use-after-free |
| C# | `sast/csharp.js` | Deserialization, SQL injection |
| DB/RLS | `sast/db-rls.js` | Supabase service-role key exposure, auth.admin client-side, bypassRowLevelSecurity, SQL tables without RLS, raw pg in handlers |
| Env hygiene | `sast/env-hygiene.js` | NEXT_PUBLIC_ secret vars, .env.example real values, hardcoded fallbacks, dotenv in non-entry files |
| Go | `sast/go-extended.js` | Go-specific security patterns |
| Host header | `sast/host-header.js` | Host header injection |
| Java deserialization | `sast/java-deserialization.js` | Unsafe Java deserialization |
| JNDI | `sast/jndi.js` | JNDI injection (Log4Shell family) |
| JWT expiry | `sast/jwt-exp.js` | JWT without expiry, weak signing |
| LLM | `sast/llm.js` | Prompt injection, LLM safety patterns |
| LLM OWASP | `sast/llm-owasp.js` | OWASP LLM Top 10 (2025) coverage |
| MCP audit | `sast/mcp-audit.js` | MCP / agent-tool security |
| Model load | `sast/model-load.js` | torch.load, pickle, trust_remote_code |
| Pipeline | `sast/pipeline.js` | CI/CD pipeline integrity |
| Prompt firewall | `sast/prompt-firewall.js` | User input in system prompt, missing max_tokens, LLM output→SQL/exec, no output validation |
| Prompt template | `sast/prompt-template.js` | Prompt template injection |
| Rate limit | `sast/rate-limit.js` | Missing rate limiting on auth/AI/payment/contact endpoints |
| Rust | `sast/rust.js` | Unsafe blocks, memory patterns |
| Solidity | `sast/solidity.js` | Smart contract vulnerabilities |
| Webhook | `sast/webhook.js` | Missing Stripe/GitHub/Clerk/Svix/Resend/Twilio signature verification |
| XXE | `sast/xxe.js` | XML External Entity injection |
| Zip-slip | `sast/zip-slip.js` | Path traversal in archive extraction |

---

## F1 BENCHMARK

The scanner is evaluated against structured ground-truth benchmarks. Every
rule ships with a `vulnerable/` + `clean/` fixture pair in `test/fixtures/`.

Local benchmark suite (33 fixture scenarios):

```bash
cd scanner && npm run bench
```

Real-world benchmark (requires internet — clones external repos):

```bash
npm run bench:realworld              # all apps
npm run bench:realworld -- --app nodegoat
npm run bench:realworld -- --app juice-shop
```

LLM/AI adversarial suite:

```bash
npm run bench:llm-goats
```

Current scores:
- Local fixture suite: **F1 100.0%** (122 TP, 0 FP, 0 FN)
- Real-world benchmarks: **F1 100%** on 33/33 apps

F1 safety rules for new rules:
1. Gate on at least 2 signals before firing (never single-regex)
2. Include `_NONPROD_RE` to exclude test/fixture/spec paths
3. New `vuln` strings must either (a) not fire on benchmark apps or (b)
   be added to the relevant app's `wildcardFamilies` in expected JSON
4. Verify with `npm run bench` after adding any new rule

