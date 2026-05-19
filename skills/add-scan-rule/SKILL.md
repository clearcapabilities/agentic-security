---
name: agentic-security:add-scan-rule
description: Walk through the canonical six-step recipe for adding a new SAST detector to this plugin — pick the right module, export a `scan*()` function, wire it into the engine, add a vulnerable/clean fixture pair, cover it in the right scoped test script, and verify with smoke + bundle build. Use this when the user says "add a rule for X", "detect Y", or "the scanner should catch Z" and we're inside this repo.
---

# Adding a new scan rule

When the user wants the scanner to detect a new vulnerability pattern, follow this workflow. Loaded on-demand, not into every session — see `scanner/src/sast/CLAUDE.md` for the same content baked into the SAST tree.

## Decision: where does this rule live?

| Shape of the rule | Module pattern |
|-------------------|----------------|
| Language-specific (e.g. Python sink, Kotlin force-unwrap) | Add to or create `scanner/src/sast/<language>.js` |
| Framework-specific hardening (e.g. Express auth, FastAPI defaults) | `scanner/src/sast/<framework>-hardening.js` |
| Cross-cutting vuln class (CSRF, prototype pollution, mass assignment) | New top-level `scanner/src/sast/<topic>.js` |
| Posture annotator (mutates existing findings) | `scanner/src/posture/` — see `scanner/src/posture/CLAUDE.md` |

If the rule is "X but with light cross-file context," still emit from `sast/` and let the cross-file annotators in `posture/cross-lang-*.js` enrich it. Don't put cross-file logic into the SAST module.

## Steps

1. **Write the detector.** Export a `scan<Name>(fileContents, opts)` function returning `Finding[]`. Required fields: `id`, `severity`, `file`, `line`, `vuln`, `cwe`, `description`, `remediation`. Set `family` and `parser` when you know them; `posture/finding-defaults.js` backfills, but detector-set wins.

2. **Wire into the engine.** Open `scanner/src/engine.js`. Add the import to the existing block (alphabetical) and call it inside `runFullScan` next to similar rules. Append the results to `finalFindings`.

3. **Add the fixture pair.** Create `scanner/test/fixtures/<rule-name>/vulnerable/` and `scanner/test/fixtures/<rule-name>/clean/`. Each holds one small file demonstrating the vulnerable / fixed shape. The vulnerable file must produce a finding; the clean file must not.

4. **Add the test.** Either extend an existing topical test (e.g. `test/python-sinks.test.js`) or create `test/<rule-name>.test.js` modelled on the smallest existing test. Wire the file into the matching scoped script in `scanner/package.json` (`test:sast`, `test:dataflow`, etc.).

5. **Verify.** Use the scoped script that covers what you touched (`npm run test:smoke`, `npm run test:sast`, `npm run test:dataflow`, …). Always include `npm run test:lifecycle` — it catches a rule that ships without an `engine.js` wire-up. The full `npm test` is the CI gate but is usually overkill for a single new rule.

6. **Rebuild the bundle if anything outside `src/` will consume it.** `npm run build`. Then `npm run smoke` to check the CLI path. If bundle smoke disagrees with unit-test smoke, you have an `engine.js` wiring miss — unit tests run against `src/` directly, but the bundle re-binds at build time.

## Common pitfalls

- **Comments confuse regex detectors.** Always go through `blankComments()` from `scanner/src/sast/_comment-strip.js` before scanning a file body. Otherwise a vuln pattern inside a `// example:` block fires.
- **Snippet attribution.** For multi-line sinks (`exec('ping ' + req.body.host, …)`), the match offset and the readable sink line can diverge. Use the actual sink expression for the finding's `snippet`, not `lines[regex.lastIndex]`.
- **Severity floor.** Don't emit `critical` without strong evidence. `annotateExploitability` will lift `high` to `critical` when production context warrants. A flood of false criticals drowns real ones.
- **Family field.** If you can't pick a `family`, the rule probably covers too much. Split it.
- **Bench-shape isolation.** If your rule needs answer-key signals to fire correctly (file naming, label markers), it goes under `scanner/src/sast/bench-shape/` and stays gated by `AGENTIC_SECURITY_BENCH_SHAPE=1`. Never make a production rule depend on bench shape.

## Verify the wiring

After step 5 the lifecycle test should pass with the new file. If it fails with "exported X has no external call site," you forgot step 2 — go back and add the import + call in `engine.js`.

If `npm run smoke` reports the new rule fires in `clean/` (false positive on the clean fixture), tighten the regex/AST match. If it doesn't fire in `vulnerable/`, your match shape is wrong — look at the actual fixture content with the actual detector and trace where it diverges.

## When to stop

You're done when:
- Both fixtures behave as expected
- The scoped test passes
- `npm run test:lifecycle` passes
- `npm run build && npm run smoke` produces the same finding count via the CLI as the unit test reported
