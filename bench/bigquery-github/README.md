# BigQuery GitHub coverage bench

Real-world stress test for the scanner: pull a stratified sample of
source files from the BigQuery `bigquery-public-data.github_repos`
public dataset, scan every file in blind mode, and aggregate per-language
**false-positive density**, **crash/timeout rate**, and **performance**.
The output drives rule hardening; it is not a published quality number.

## What this bench measures and what it does NOT

| Measured | Not measured |
|---|---|
| Findings-per-KLoC per language (proxy for FP density on mostly-OK OSS code) | Recall — no ground-truth labels exist at this scale |
| Crash / timeout rate per 10k files | Per-file accuracy |
| p50 / p95 per-file scan latency | Severity calibration |
| Top FP clusters per language | F1 / precision (without manual labeling — see Stage 4 in workflow below) |

**Recall is intentionally out of scope.** Inventing labels at this scale
would re-create the self-reference problem the curated benches already
have. To get a real precision number, run the optional **Stage 4**
labeling pass on a stratified sample of findings.

## Output policy

Per-cycle output (under `cycle-<YYYY-MM-DD>/`) is **gitignored** and
**local-only**. The harness deliberately makes it hard to publish
per-repo or per-file findings from this corpus:

- `cycle-*/files/` contains source from third parties under permissive
  licenses. Never republished.
- `cycle-*/findings.jsonl` carries raw scanner output keyed by repo + file
  path. Never committed.
- Only **language-aggregate** summary tables in `cycle-*/summary.md`
  are reviewable, and even those should not be cited externally without
  a precision-on-real-code labeling pass behind them.

See `docs/audit/README.md` for the project policy on publishing
benchmark numbers.

## Layout

```
bench/bigquery-github/
├── README.md                ← this file
├── manifest.example.yml     ← schema for per-cycle metadata
├── query/
│   ├── stratified.sql       ← parameterized BigQuery query
│   └── README.md            ← how to run the query
├── ingest/
│   └── materialize.mjs      ← NDJSON → content-hashed fixture tree
├── bin/
│   ├── scan-cycle.mjs       ← per-file scan with timeout, writes findings.jsonl
│   └── run-cycle.mjs        ← end-to-end orchestrator (materialize → scan → score)
├── score/
│   ├── fp-density.mjs       ← findings-per-KLoC per language
│   ├── stability.mjs        ← crash + timeout aggregator
│   └── cluster.mjs          ← top-N finding clusters per language
└── _self-test/
    └── files/               ← tiny multi-language fixture for smoke-testing
                                the scoring pipeline without BigQuery
```

## Workflow (per cycle)

```
1. Run the BigQuery query → NDJSON dump.       [external: needs `bq` + a billing account]
2. Materialize files locally.                  bin/run-cycle.mjs --materialize <ndjson>
3. Scan every file, blind mode, with timeout.  bin/run-cycle.mjs --scan
4. Aggregate.                                  bin/run-cycle.mjs --score
5. (Optional, recurring) Manually label a      Stage 4 — see below.
   stratified subset of findings for precision.
```

Or one-shot: `bin/run-cycle.mjs --all <ndjson-file>`.

## Stages

### Stage 0 — license + privacy review (one-time)

Confirm the dataset's license terms allow programmatic scanning + storage
of derived metrics. The dataset samples permissively-licensed OSS, but
findings derived from it should never be republished per-repo without
the original repo owner's permission. Policy lives in
`docs/audit/README.md`; this harness enforces it by gitignoring all
per-cycle output and committing only language-aggregate summaries.

### Stage 1 — stratified sample

Run `query/stratified.sql` against BigQuery. The query is parameterized
by language and per-language file count. Defaults:

| Language | Files | Priority rationale |
|---|---:|---|
| C# | 2,000 | Highest priority — current blind F1 = 1% on Juliet C#. |
| C / C++ | 5,000 | Priority — current blind F1 = 8% on Juliet C/C++. |
| Java | 3,000 | Long tail uncovered — Juliet Java F1 = 42%. |
| Python | 5,000 | No external bench data. |
| JavaScript | 5,000 | No external bench data. |
| TypeScript | 5,000 | No external bench data. |
| Go | 3,000 | No external bench data. |
| Ruby | 2,000 | No external bench data. |
| PHP | 2,000 | No external bench data. |
| Kotlin | 1,500 | No external bench data. |
| Swift | 1,500 | No external bench data. |
| Rust | 1,500 | No external bench data. |
| Solidity | 1,500 | No external bench data. Smaller universe — pull aggressively. |
| Dart | 1,000 | No external bench data. |

≈ 40k files. Each language uses a stratified mix: random sample,
top-starred subset, recent-commit subset. See `query/README.md`.

### Stage 2 — scan + collect

`bin/scan-cycle.mjs` loops over every materialized file, invokes
`runScan` with `opts.fileContents = { [path]: content }`, applies a
per-file 30-second timeout via `Promise.race`, and streams one JSONL
line per file to `cycle-<date>/findings.jsonl`. Blind mode
(`AGENTIC_SECURITY_BLIND_BENCH=1`) is forced on so corpus-shape gates in
the engine cannot bias the result.

Crashes and timeouts are recorded as `{ status: "crash" | "timeout",
file, lang, error }` lines — they do not abort the cycle.

### Stage 3 — adversarial review (manual)

`score/cluster.mjs` surfaces the top-20 most-frequent finding clusters
per language. Manually inspect each cluster. The likely outcomes:

- a rule fix (lands in `scanner/src/sast/`)
- a regression fixture (lands in `scanner/test/fixtures/`)
- a new detector if the cluster identifies an under-served pattern
- a known FP that needs a new sanitizer or exclusion

### Stage 4 — precision-on-real-code (optional, recurring)

Randomly sample 100 findings per language. Manually label each
TP / FP / refused. Compute per-language precision with a Wilson 95% CI.
This is the only quantitative claim about real-world quality this
harness endorses. Numbers stay local.

The labeling tool is intentionally not part of this harness — it is
manual review work, typically in a spreadsheet or Markdown checklist
under `cycle-<date>/labels/`.

### Stage 5 — recurring (½ day / month)

Rerun stages 1–3 monthly. Stage 4 quarterly. Compare per-language
FP density and crash rate against the prior cycle. The harness stores
each cycle's summary under `cycle-<date>/`; you can diff two cycles by
running the scoring scripts with `--compare <other-cycle-dir>`.

## Smoke test (no BigQuery needed)

```
node bench/bigquery-github/bin/run-cycle.mjs --smoke
```

Runs the entire pipeline against the bundled `_self-test/files/` corpus
(~6 files, multiple languages) and prints a summary. The exit code is
non-zero if the harness itself is broken (e.g. a scoring script crashes).
Useful for CI to keep the harness working without spending BigQuery
budget.

## Cost guardrails

| Guardrail | Where enforced |
|---|---|
| BigQuery $500/year cap | Project owner — not enforceable in code without a billing API integration. Per-query cost estimate printed by `query/README.md`. |
| Per-cycle local disk cap (10 GB) | `bin/scan-cycle.mjs` aborts if `cycle-<date>/files/` exceeds the cap. |
| Per-file 30s timeout | `bin/scan-cycle.mjs` (configurable via `--timeout-ms`). |
| Total cycle 4-hour timeout | `bin/run-cycle.mjs` (configurable via `--wall-timeout-min`). |

## Risks

| # | Risk | Mitigation in this harness |
|---|---|---|
| R1 | BigQuery cost overrun | Query is committed; user runs it via `bq` and pays. Per-query bytes-scanned estimate in `query/README.md`. |
| R2 | Accidentally publishing per-repo findings | `cycle-*/` is gitignored. Only `summary.md` aggregate tables are reviewable. No repo URLs in committed artifacts. |
| R3 | Sample bias toward high-quality top-starred repos | Stratified query — random sample, top-starred, recent commits, per-language. |
| R4 | Corpus changes across BigQuery refreshes | Each cycle's `manifest.yml` records the BigQuery `last_modified` of the source tables and the query SHA. Cross-cycle deltas are valid only when manifests align. |
| R5 | Scanner crashes interpreted as "bench results" | Crash rate is binary (must be near zero), not a metric to optimize. Each crash is a bug. |
| R6 | Flood of FPs we can't all triage | `score/cluster.mjs` caps at top-20 clusters per language. The long tail is recorded but not actioned. |
| R7 | Labeling drift across reviewers in Stage 4 | Optional inter-rater check on an overlap subset — not in scope of this harness, but the labels file format supports two reviewers. |
| R8 | Numbers leak into marketing | `docs/audit/README.md` policy: no single-corpus or pre-labeling numbers in user-facing docs. |

## How to know it's working (six-month checkpoint)

The bench is **successful** if:

- All 14 GA languages have at least one cycle on record.
- Top-3 priority languages (C#, C/C++, Python) have had at least one
  rule fix motivated by the bench, and FP density has measurably
  dropped on the next cycle.
- A precision-on-real-code labeling pass has run for at least the top-3
  priority languages, with internally-published precision + CI.

The bench is a **failure** if:

- Stage 4 labeling never happens — without labels the FP density
  numbers are uncalibrated.
- Per-language FP densities get cited externally as quality evidence
  even though they have no precision calibration.
- BigQuery costs exceed the cap without producing actionable rule fixes.

## Open methodology questions

- Should the harness snapshot each cycle's input file list (content
  hashes) into `manifest.yml` so the exact corpus is reproducible? Cost
  vs determinism tradeoff — BigQuery tables are mutable.
- Continuous-integration cadence: monthly cron vs. release-gated?
  Probably release-gated initially (cheaper, simpler).
- Public-facing methodology page (no numbers) once Phase 1 is stable —
  worth doing for transparency, not yet.
