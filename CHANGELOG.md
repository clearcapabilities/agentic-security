# Changelog

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
