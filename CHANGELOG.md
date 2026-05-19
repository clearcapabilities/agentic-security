# Changelog

## 0.50.0 — next-gen SAST Phase 1 complete (5 of 5 units)

Closes Phase 1 of `docs/PRD-next-gen-sast-phase1.md`. The two units queued
from v0.49.0 (P1.2 verifier sandbox, P1.4 polyglot bench) are now wired.

### Shipped & wired

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** New
  module `scanner/src/posture/verifier.js`. Consumes the `f.poc` artifacts
  from P1.1 and assigns a per-finding `verifier_verdict`:
  - `verified-exploit` — PoC ran against a live target and exited 0
  - `verified-by-llm` — Layer-3 LLM accepted the finding
  - `verified-sanitizer-absence` — pattern-based proof that no sanitizer
    appears in a ±10 line window around the sink (9 vuln families covered)
  - `unverified-by-design` — CWE family where v1 explicitly doesn't ship a PoC
  - `cannot-verify` — sandbox error, missing target, PoC validation failed

  PoC static validation refuses destructive shell payloads, hardcoded cloud
  metadata IPs, runaway-length code, and Node PoCs without a deterministic
  `process.exit(...)`. Sandbox execution mode (opt-in via
  `AGENTIC_SECURITY_VERIFY_LIVE=1` + `AGENTIC_SECURITY_VERIFY_TARGET=<url>`)
  runs each PoC under Docker with `--cap-drop=ALL --memory=256m --read-only
  --user=nobody`; falls back to subprocess with `ulimit` when Docker isn't
  available. Fail-closed: any error → `cannot-verify`, never silent drop.
  New CLI subcommand `agentic-security verify [--finding <id>] [--live
  --target <url>]` re-runs the verifier loop on `last-scan.json` and
  persists the verdicts. Smoke on `vulnerable-js` fixture: 7 findings get
  `verified-sanitizer-absence` static proofs; 2 get `unverified-by-design`;
  the rest are `cannot-verify` pending live execution.

- **P1.4 — Cross-language polyglot benchmark (G3).** New `bench/polyglot/`
  with a tiny dependency-free YAML parser, the runner `runner.mjs`, and 4
  starter cases:
  - 01 HTTP→Python SQL (canonical Phase-2 detector gap — Python SAST)
  - 02 Queue→Python cmd (same gap; queue chain detected; sink not yet)
  - 03 ORM round-trip (Node-only; mass-assignment + data-exposure TPs)
  - 04 HTTP→Node SQL (clean end-to-end test of the OpenAPI cross-asset bridge)

  Default mode `recall-only` measures "does the chain fire where it
  should?" rather than penalizing incidental findings (header-hardening,
  CSRF on test routes, body-parser DoS warnings). Set `mode: strict` in a
  manifest for full-precision scoring. Current overall F1 = 72.7%; PRD G3
  target is 85%; the 27pp gap is Python-side detector coverage (Phase 2).
  New `npm run bench:polyglot`.

### Tests, bench, integrity

- 19 new tests in `test/verifier.test.js` (validation, sanitizer proofs,
  verdict assignment, batch annotation, fail-closed defense-in-depth).
- All 218 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- Polyglot bench F1 72.7% (above 30% v1 floor; below 85% G3 target — the
  gap is documented in `bench/polyglot/README.md`).
- No new dead exports.

### Honesty correction

The PRD's G2 target ("≥80% of high+/critical findings ship with a verified
PoC") is not measured yet — that requires a labeled run-against-target,
which the v1 verifier supports via `--live --target` but we haven't built
a target harness. v1 ships the framework; the labeled measurement is
Phase 5 work.

## 0.49.0 — next-gen SAST Phase 1 (3 of 5 units)

Implements 3 of the 5 Phase-1 shippable units from
`docs/PRD-next-gen-sast-phase1.md` (parent `docs/PRD-next-gen-sast.md`).
The two queued for the next session are noted at the end.

### Shipped & wired

- **P1.1 — PoC generator framework (FR-VER-2).** New module
  `scanner/src/posture/poc-generator.js` ships runnable proof-of-concept
  files for the top-10 CWE families from the parent PRD: SQL injection,
  command injection, XSS, path traversal, SSRF, code injection, CSRF, open
  redirect, XXE, and insecure deserialization. Each PoC is a self-contained
  Node script with one `fetch()` call, evidence-pattern detection, and a
  deterministic exit code (0 = exploit demonstrated, 1 = not demonstrated, 2
  = error). Templates respect a safety policy: no destructive shell commands,
  no real cloud-metadata IPs, no outbound network beyond localhost. Smoke:
  scanning `test/fixtures/vulnerable-js` produces 8 PoCs across 6 distinct
  CWE families. Findings get a new `f.poc = { lang, kind, cwe, family, runHint, code }`
  field surfaced in normalizeFindings and SARIF. Families without v1 template
  coverage get `f.poc = null` and a documented entry in
  `poc-cwe-map.js::NO_POC_FAMILIES`.
- **P1.3 — Brier-calibrated confidence (FR-UX-1, FR-UX-2).** New module
  `scanner/src/posture/calibration.js` turns the ordinal `confidence` score
  into a calibrated probability with 95% Wilson confidence interval. Per
  finding: `calibrated_confidence`, `calibrated_confidence_ci`,
  `calibrated_n`, `calibration_reason` (set when null — "insufficient-samples"
  / "no-family" / "no-history"). Seed corpus in
  `calibration-seed.json` covers 20 vuln families from the OWASP Benchmark +
  Juliet labeled runs; the customer's `.agentic-security/validator-metrics.json`
  overrides per-family when sample count is higher. Calibration is honest
  about uncertainty: `MIN_SAMPLES_FOR_CALIBRATION = 30`. The PRD G1 target
  (Brier ≤ 0.10 on a held-out labeled set) is queued for Phase 5; this ships
  the framework, the math, and the seed data.
- **P1.5 — Cross-language message queues (FR-XSAT-4).** New module
  `scanner/src/posture/cross-lang-queues.js` indexes producer and consumer
  call sites for Kafka (kafkajs, kafka-clients, confluent-kafka), AWS SQS
  (aws-sdk, boto3), RabbitMQ (amqplib, pika, Spring `RabbitTemplate`), Redis
  Streams (XADD / XREAD across Node, Python, Go), and Google Pub/Sub. When
  producer and consumer agree on a topic name and the consumer file has a
  high+ finding, we emit a `cross_language: true` chain back to the producer
  (and vice-versa). Severity is demoted one tier so the chain doesn't double-
  count in severity bucketing. Honest about uncertainty: only literal-string
  topic matches; constant-folded names left for Phase 2.

### Tests, bench, integrity

- 14 new tests in `test/poc-generator.test.js` (PoC coverage + safety).
- 9 new tests in `test/cross-lang-queues.test.js`.
- 14 new tests in `test/calibration.test.js` (Wilson + Brier + annotation).
- All 199 + 26 + 2 unit tests pass.
- Synthetic-bench F1 still 100%.
- No new dead exports; `test/no-dead-modules.test.js` both subtests pass.

### Queued for next session

- **P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7).** Needs
  Docker integration, network isolation, and a sandbox-escape test. The PoC
  generator already produces files; the verifier executes them in isolation.
- **P1.4 — Cross-language polyglot benchmark (G3).** Needs fixture builds
  across Node → Python → Java → Postgres. Measures the cross-asset claims
  we've now made for HTTP/gRPC/GraphQL/ORM/IaC/Queues.

### Honesty correction

The parent PRD claimed v1.0.0 ships at ~15 months. This release is one
session of work; we're at ~v0.49.0 on a path to v0.50.0 (Phase-1 release).
The PRD's G1 (Brier ≤ 0.10 on a held-out set) is not yet measured — the
shipped calibration is on the SEED corpus, which is by definition not held
out. We surface this in the `_caveat` field of `calibration-seed.json`.

## 0.48.0 — fourth-round premortem + CI bench failure

### Bench regression fix

The synthetic-bench CI job started failing at v0.47.0. Two issues:

- **Root-cause clustering over-merged across detectors.** Two distinct
  detectors (structural `Open Redirect` and `host-header`) that share CWE-601
  on the same `res.redirect(...)` line were collapsing into one finding,
  hiding the host-header bug. `sinkKey` now includes `f.parser` so two
  detectors never merge. Empty `sinkExpr` keys are skipped (was bucketing all
  rate-limit findings into one).
- **Two expected entries pointed at the same post-clustered line.** Cleaned
  up `expected.json` for `orm-raw-sql` and added six new `csrf` family
  expected entries for fixtures that legitimately lack CSRF protection.
  Baseline refreshed.

### Node 20 deprecation

Bumped `actions/{checkout,setup-node,upload-artifact}` to v5 and
`actions/github-script` to v8 (Node 24 native). Dropped the
`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround env.

### Fourth-round premortem — 15 findings closed

- **4R-1**: rule-pack signing is fail-closed in CI. When `CI=true` (and the
  common variants) and no signing keys are configured, pass-through mode
  refuses rather than silently accepting. Opt-in via
  `AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1`.
- **4R-2**: `scanner/dist/agentic-security.mjs` is now correctly tracked in
  `.gitignore`. The previous "Not committed" comment lied — the bundle was
  always committed, the comment was wrong. Now `dist/*` is ignored except
  `agentic-security.mjs` and `agentic-security.mjs.sha256`.
- **4R-3**: `scan.yml` downloads the bundle with checksum verification. New
  `scanner-ref` workflow input lets callers pin to a release tag or commit SHA
  for supply-chain hardening. `scanner/dist/agentic-security.mjs.sha256` is
  generated by `npm run build` and committed.
- **4R-4**: catalog `filterByProvenance` memoizes per (entries, mode) so the
  taint hot path no longer allocates a fresh array per match.
- **4R-5**: LSP `_depCache` is granularly invalidated on manifest save — only
  the saved file's entry is refreshed, not the whole project tree.
- **4R-6**: `no-dead-modules.test.js` has a sister "allowlist decay" check.
  Stale ALLOWLIST entries (25 of them, from v0.47.0) were removed.
- **4R-7**: `version.js` warns to stderr when `package.json` can't be read
  instead of silently falling back to `'unknown'`.
- **4R-8**: `applyFix` accepts `stableId` from the caller (`bin/` and `mcp/`)
  rather than re-deriving via `findingId`, which rotates on line-shift.
- **4R-9**: fix-history stale-lock reap is PID-aware. Only unlinks when the
  PID is dead OR the file's old AND the PID is unkillable. Atomic re-read of
  the lockfile before unlink avoids racing a fresh acquirer.
- **4R-10**: SARIF emits a tri-state `signatureStatus: 'verified' | 'unsigned'
  | 'pass-through'` field. The legacy `_unsigned` / `_passThroughSigning`
  flags are emitted alongside for one release of grace.
- **4R-11**: CLI and Markdown reports now render `validator_verdict` so SCA
  findings tagged `not-applicable` aren't invisible to the reader.
- **4R-12**: custom-rules deadline is per-scanRoot, accumulating across calls
  within a process. New `resetCustomRulesBudget(scanRoot)` for long-lived LSP
  scans; wired into the LSP server.
- **4R-13**: `prepublishOnly` refuses to overwrite a locally-edited
  `scanner/CHANGELOG.md` that differs from the canonical `../CHANGELOG.md`.
- **4R-14**: new `scripts/nist-compliance/test_regex_redos.py` asserts every
  import regex runs in linear time on pathological input — guards against
  re-introducing the `(?:[^)]|\n)+?` ReDoS fixed in `e0c669b`.
- **4R-15**: `PROMPT_VERSION` is now a public export of `llm-validator/index.js`.
  The `validator-cache gc` subcommand no longer reaches through the
  underscore-prefixed `_internal` private API and fails loudly if the version
  can't be read.

### Honesty note

All 15 fourth-round findings are closed without dead code (verified by the
no-dead-modules test). The bench failure was a real regression introduced
in v0.47.0 (clustering by CWE alone) — caught by CI, fixed by adding
`f.parser` to the cluster key.

## 0.47.0 — third-round premortem remediation

Third adversarial premortem identified 17 findings against the v0.46.0
remediation. All 17 are now closed. Highlights:

- **3R-1: integration test for dead exports** — new `test/no-dead-modules.test.js`
  walks `scanner/src/{posture,llm-validator,dataflow,lsp,ir,mcp}` and asserts
  every exported symbol has at least one external call site (`.js` files and
  `commands/*.md`). Allowlist for legitimate library-style exports. Closes the
  recurring "wired in code review, dead in code" failure mode.

- **3R-2 / 3R-3: single-sourced version** — `scanner/src/posture/version.js`
  reads `scanner/package.json#version` at module load; SARIF `tool.driver.version`
  and `CURRENT_RULESET_VERSION` now derive from it instead of independently
  hardcoded constants that diverged on every release.

- **3R-4: signing graceful degradation** — `rule-pack-signing.js` operates in a
  pass-through mode when both bundled and project keys are absent. One audit
  warning per session; findings carry `_passThroughSigning:true`. Set
  `AGENTIC_SECURITY_STRICT_SIGNING=1` to disable pass-through.

- **3R-5: CLI keygen safety rails** — `agentic-security-rule keygen` refuses
  `--out` paths under `.agentic-security/`; warns on non-TTY stdout without
  `--out`; writes private-key files mode 0600. `--i-understand-private-keys`
  to override.

- **3R-6: provenance surfaced in reports** — `normalizeFindings` carries
  `_unsigned` and `_passThroughSigning` through; SARIF `result.properties`
  emits `unsigned:true` / `passThroughSigning:true`; SARIF
  `invocations[].properties` now includes `rulesetVersion`, `rulesetVersionSource`,
  and `rulesetVersionMismatch` for trend attribution.

- **3R-7: requiresReAudit is now load-bearing** — `bench-realworld.js` reads
  curated expected JSONs' `requiresReAudit:true`, emits a stderr warning per
  affected corpus, and tags the corpus result with
  `requiresReAudit:true` so consumers know its F1 is informational.

- **3R-8: global deadline for custom rules** — `applyCustomRules()` now caps
  the total scan time across all files and all rules at 30s (overridable via
  `AGENTIC_SECURITY_CUSTOM_RULES_BUDGET_MS`), guarding against ReDoS sprees
  across many files even when each individual regex respects its 200ms budget.

- **3R-9: LSP dep-cache invalidation on manifest save** — saving any
  `package.json`/`pyproject.toml`/`Cargo.toml`/etc. now invalidates the cached
  dep snapshot before re-scanning, so freshly added vulnerable packages and
  removed ones reflect immediately in editor diagnostics.

- **3R-10: catalog OFFICIAL_ONLY is per-match** — `AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1`
  is now read per source/sink match instead of once at module load, so CI lanes
  that toggle strict mode just before invocation are actually honored.

- **3R-11: validator preflight handles SCA locators** — findings with
  `parser:'SCA'` or `pkg`/`component`/`purl` set are tagged
  `validator_verdict:'not-applicable'` rather than `'unvalidated'`, which
  was misleading for findings that an LLM cannot meaningfully judge.

- **3R-12: applyFix recover() cross-checks against last-scan.json** — the
  fix-history log entry records the matching finding's stableId at apply
  time; `recover()` after a crash now tags promoted entries as
  `applied-stale` when the finding has vanished from last-scan.json.

- **3R-13: file lock around log writes** — concurrent `applyFix`, `recover`,
  and `undo` invocations no longer race the `log.json` write; serialization
  via `log.lock` with 30s stale-lock reaping and 5s contention timeout.

- **3R-14: validator-cache GC subcommand** — `agentic-security validator-cache
  stats|gc [--older-than N] [--dry-run]` prunes `.agentic-security/llm-cache/`
  by age and prompt-version mismatch.

- **3R-15: tier cutoffs stable under 2-decimal rounding** — confidence tier
  (`high|medium|low|very-low`) is now derived from the 2-decimal display value,
  so a finding reported as "0.75" never lands in two tiers depending on the
  viewer's rounding.

- **3R-16: CHANGELOG ships with npm package** — `prepublishOnly` copies
  CHANGELOG.md into `scanner/`; added to `package.json#files`. The repo-root
  copy remains canonical; the in-package copy is gitignored.

- **3R-17: fix-history log compaction** — `agentic-security undo --compact
  [--retain-days N] [--prune-backups]` archives terminal entries (reverted,
  failed, applied-stale) older than the retention window into
  `log-archive-YYYY-MM.json`, optionally pruning their `.bak` files.

### Honesty correction

No claims in this release exceeded what shipped. v0.47.0 closes the 17
third-round premortem findings against v0.46.0 cleanly; the round-4 premortem
will surely find more, and that is fine.

## 0.46.0 — second-round premortem remediation + honesty correction

### Honesty correction for v0.45.0

The v0.45.0 commit message (`3acca6b fix(security): premortem remediation —
all 15 findings`) claimed all 15 first-round premortem findings were
remediated. A second-round adversarial premortem identified five of those
"closures" as dead code or wire-up regressions:

- `posture/fix-history.js::recover()` was exported but never called from
  any startup path → pending entries from a crashed `applyFix` accumulated
  forever. **Now fixed**: wired into `runScan.js` at top of every scan.

- `posture/ruleset-version.js::stampScan()` / `effectiveVersion()` were
  exported but never imported → ruleset-pinning was documentation only.
  **Now fixed**: wired into `runScan.js` to stamp every scan result.

- `posture/validator-metrics.js::recordTriage()` was exported but the
  `/triage` slash command did not invoke it → per-CWE production metrics
  never accumulated. **Now fixed**: `/triage` now calls `recordTriage` on
  every verdict (subject to the new symmetric learn gate).

- The custom-rules pipeline tagged unsigned RULES with `_unsigned: true`
  but the per-finding emitter (`toFinding`) did not copy the marker →
  the audit chain promised by the warning log did not exist in the data.
  **Now fixed**: findings now carry `_unsigned: true` when their rule does.

- `engine.js:6941` called the LLM validator with `concurrency: 4`,
  overriding the validator's `concurrency: 1` determinism default →
  cache-cold runs produced non-deterministic SARIF in the same commit
  that promised determinism. **Now fixed**: respects `AGENTIC_SECURITY_LLM_CONCURRENCY` env (default 1).

### Other second-round fixes

- **String-aware JSON parser** in the LLM validator. Previous
  `parseLastJsonObject` ignored string-state and could be fooled by braces
  inside JSON string literals. Rewritten to walk forward with full string-
  and escape-state tracking, then return the LAST valid candidate.

- **Empty file/line pre-flight** in `validateOne`. A validator response of
  `{"file":"","line":0,...}` trivially satisfied the cross-check on findings
  without precise location. Now refused with `unvalidated`.

- **Protected signing trust root**: trusted keys come from a built-in
  constant (`BUNDLED_OFFICIAL_KEYS`); project-local `.agentic-security/trusted-keys.json`
  is refused unless `AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1` is set
  (audit-logged). A PR contributor can no longer bootstrap a key into trust.

- **Key revocation**: trusted-keys.json `crl[]` honored (signature-hash
  blacklist); `revokedAt` field on each key honored (signatures dated after
  revocation refused).

- **`agentic-security-rule` CLI** for `keygen` / `sign` / `verify` with a
  first-time setup walkthrough and explicit private-key-handling warnings.

- **Symmetric AGENTIC_SECURITY_LEARN gate**: `/triage` no longer writes
  verdicts to `triage-feedback.json` without explicit opt-in. Prevents an
  attacker from poisoning the file in advance of someone flipping the
  read-side flag.

- **Worklist deadline check**: deep-mode taint engine honors `deadlineMs`
  inside `analyzeFunction`'s worklist (every 128 iterations). Pathological
  CFGs can no longer hold past the global timeout.

- **LSP loads dep-manifest files**: per-save scan in `lsp/server.js` now
  pre-walks the project tree once for `package.json` / `pom.xml` / `.proto`
  / `.graphql` / `.tf` so SCA + cross-language passes have their inputs.

- **SARIF notifications for caveats**: `tool.driver.notifications` and
  `invocations.toolExecutionNotifications` now carry the load-bearing
  warnings (priority scores are ordinal, OWASP Benchmark numbers are
  benchmark-tuned). Customer CI ingesters see them without reading docs.

- **Re-sanitization on cache read**: validator reasoning passes through
  `sanitizeReasoning` again on cache hit (defense in depth against any
  future write-path regression).

- **Provenance + requiresReAudit fields** added to all 25 bootstrapped GT
  files under `bench/.../expected/`. Machine-readable signal that the
  bootstrap origin is self-referential.

### What this commit honestly does NOT close

- BUNDLED_OFFICIAL_KEYS is empty — a production deployment needs the
  maintainers to generate a real keypair, distribute the private key
  offline, and ship the public key. Today's effective behavior is "no
  official keys, project keys via opt-in."
- The CVE-replay corpus is still 1 starter entry (G1 second half remains
  not delivered).
- Real-world Java F1 generalization is still unmeasured.

## 0.45.0 — first-round premortem remediation

(See commit 3acca6b. Some closures were dead-code; see honesty correction
above.)

## 0.44.0 — multi-session items: gRPC/GraphQL/ORM cross-lang, IDE plugins

## 0.43.0 — small engineering items: MCP verify_fix/synthesize_fix,
SentQL path predicates, conversation-context hook, fix-plan,
per-CWE metrics

## 0.42.0 — Layer 1 IR + Layer 2 interprocedural taint, F1=0.907 on
OWASP Bench v1.2 (blind, strict)
