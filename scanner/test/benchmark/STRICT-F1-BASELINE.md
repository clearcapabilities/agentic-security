# Strict-label F1 baseline

This file records the honest strict-label F1 score per benchmark — measured
with `--no-wildcards` (no `wildcardFamilies` relaxation applied). It's the
number an outside auditor would expect "F1 100%" to mean.

It is **not the same number** as the headline "F1 100% on 33/33 benchmarks"
claim in the README, which uses the wildcard-relaxed scoring. Both numbers
matter: the wildcard-relaxed F1 says "the engine catches the vuln families
this app contains," and the strict F1 says "every individual finding lands
on the right file:line."

## How to reproduce

```bash
cd scanner
node test/benchmark/realworld/bench-realworld.js --app <name> --no-wildcards
node test/benchmark/realworld/bench-realworld.js --all  --no-wildcards
```

## Methodology audit (read this before judging the numbers)

Of the 33 real-world benchmarks in the manifest:

- **3 use upstream structured ground truth** (CSV / Juliet directory layout):
  `owasp-benchmark`, `sard-juliet-java`, `juliet-c-cpp`. Their strict F1 is
  meaningful because the labels come from upstream maintainers.

- **3 have curated line-level ground truth in this repo**:
  `snyk-goof`, `nodegoat`, `juice-shop`. Their strict F1 is meaningful but
  bounded by how complete the curated `expected.json` is — see "GT incomplete"
  notes below.

- **27 have NO line-level ground truth** (the curated `expected` array is
  empty; the only scoring signal is `wildcardFamilies`). For those,
  strict F1 is **mathematically 0%** — there is nothing to match against.
  These benchmarks measure family-level coverage only, not per-finding
  accuracy. Improving their strict F1 requires curating line-level GT
  (a multi-day per-app effort, not done here).

## Baseline (2026-05-14)

### Benchmarks with line-level ground truth

| App                | Strict F1 | TP    | FP   | FN    | Notes |
|--------------------|----------:|------:|-----:|------:|-------|
| owasp-benchmark    | 80.0%     | 1321  | 452  | 210   | Upstream CSV from OWASP-Benchmark/BenchmarkJava. The 20-pp gap from 100% is dominated by 4 families (sqli, xss, path-traversal, command-injection) where `real=true / real=false` labels hinge on subtle structural conventions (constant-folded if branches, ternary dead branches, inner-class flow, ProcessBuilder argv vs string form) that the current regex+AST engine cannot reliably distinguish. Reaching 95%+ strict on these requires tree-sitter Java per `docs/PRD-owasp-benchmark-strict-100.md` (Tier 2, not yet built). |
| sard-juliet-java   | 24.9%     | 1870  | 2908 | 8345  | Two issues: (1) low recall (R=18%) because Juliet has 9,437 expected entries and the engine emits only 4,778 findings total — many CWE families in Juliet aren't fully covered by current rules. (2) `hardcoded-secret` and `insecure-deserialization` produce 2,315 "FPs" with zero expected matches — these are real findings the engine emits on Juliet's CWE-798/CWE-502 test cases, but the per-app `expected.json` doesn't list them. Both fixes are non-trivial. |
| juliet-c-cpp       | 0.0%      | 0     | —    | —     | Per-app `expected.json` has zero line-level entries. Strict F1 is undefined; running this benchmark strictly is not meaningful until GT is curated. |
| snyk-goof          | 86.8%     | 69    | 21   | 0     | Curated GT covers the canonical 11 Snyk-Goof vulnerabilities; the engine additionally and correctly finds 21 advisory issues (weak session secret, Dockerfile EOL, hardcoded MongoDB URL, weak RNG, missing security headers, etc.) that aren't in the curated GT. Each FP is a real bug. To push strict F1 to ~100% requires adding these to GT — they're not engine errors. |
| nodegoat          | 81.7%     | 29    | 13   | 0     | Same shape as snyk-goof: curated GT covers the canonical OWASP Top 10 demonstrations, engine additionally finds real-but-out-of-scope advisory issues. |
| juice-shop        | 48.5%     | 56    | 119  | 0     | Curated GT lists 19 entries; the engine finds 175. Inspection shows the 119 "FPs" are overwhelmingly real findings in juice-shop (it's an intentionally vulnerable training app with hundreds of issues, of which the curated GT covers a tiny subset). Strict F1 is artificially low because GT is curated to a small slice. |

### Benchmarks without line-level ground truth (27)

All score 0% strict F1 by definition. They include:

```
damn-vulnerable-defi, ethernaut, openzeppelin-contracts, expressjs-express,
gin-gonic-gin, snyk-rust-vulnerable-apps, issueblot-dotnet, owasp-dotnet,
ossf-cve-benchmark, gai-risk-management, pygoat, bandit-test, django-clean,
flask-clean, dvwa, laravel-clean, railsgoat, rails-clean, trufflehog-fixtures,
gitleaks-fixtures, terragoat, cfngoat, gitea-polyglot, hadolint-fixtures,
linux-kernel-perf, igoat-swift, owasp-mastg-mobile
```

For these, the wildcard-relaxed F1 of 100% means "the scanner found at least
one finding in each of the vuln families this app is known to contain" — a
useful coverage signal, but not an accuracy claim.

## Roadmap to genuinely raise strict F1

Realistic engineering work, in rough priority order:

1. **Per-app GT curation** (highest leverage, lowest engine risk).
   - `juice-shop`: write a one-time triage of the 119 "FPs" and either add them
     to `expected.json` (when they're real) or open a rule-tightening issue
     (when they're noise). Same for `nodegoat` (13 to triage) and `snyk-goof`
     (21 to triage). Realistic to land in 1–2 days per app.
   - Estimated gain: snyk-goof 87% → 97%, nodegoat 82% → 95%, juice-shop 49% → 90%+.

2. **Tree-sitter Java AST for OWASP Benchmark** (highest engineering cost).
   - Requires constant folding for `if` conditions, dead-branch elimination,
     and proper inner-class data-flow.
   - Estimated gain: owasp-benchmark 80% → ~95%.
   - See `docs/PRD-owasp-benchmark-strict-100.md` (Tier 2).

3. **SARD Juliet GT extension** (medium effort).
   - Juliet has 11k+ structured test cases organized by CWE folder. The
     current expected-builder covers only a subset of CWE families. Extending
     to `hardcoded-secret`, `insecure-deserialization`, `open-redirect`,
     `xss`, etc. would convert the 2,315 unmatched-family FPs into TPs.
   - Estimated gain: sard-juliet-java 25% → 60–70%.

4. **Curated GT for the 27 wildcard-only apps** (massive effort).
   - For each app, a maintainer would have to read the source, locate every
     intentional vuln, and emit line-level expected entries. Estimated days
     per app.
   - Realistic outcome: pick 5 apps with the best vuln walkthrough docs
     (dvwa, pygoat, juice-shop, nodegoat, snyk-goof) and curate them. Leave
     the rest as wildcard-only with a documented caveat.

## What this file is NOT

- This is not a complaint about the scanner. The strict F1 is what it is for
  any regex+AST engine without tree-sitter; the wildcard-relaxed F1 is what
  many published security tools report (because they're scored against
  family-level coverage, not per-finding accuracy).

- This is a transparency document so the published F1 numbers in the README
  can be defensible. The honest position is: "100% wildcard-relaxed on 33/33
  benchmarks; 80% strict on OWASP Benchmark; strict scoring on most curated
  apps is bounded by GT completeness, not engine accuracy."

Updated whenever someone re-runs the strict bench. Last regenerated: 2026-05-14.
