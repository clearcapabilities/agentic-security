# Running the stratified BigQuery query

Prerequisites: the `bq` CLI (part of the Google Cloud SDK) authenticated
against a billing-enabled project. Install:
<https://cloud.google.com/sdk/docs/install>.

## Cost estimate (per language)

These are approximate bytes-scanned figures for `stratified.sql` against
the public dataset. Multiply by current BigQuery on-demand pricing
(roughly $5 per TB at the time of writing — confirm in your billing
console) for the per-query dollar cost.

| `@lang_ext` | Sample size | Bytes scanned (approx) | Approx cost |
|---|---:|---:|---:|
| `cs` | 2,000 | 3–6 GB | $0.02–0.03 |
| `c`, `cpp`, `cc`, `cxx`, `h`, `hpp` | 5,000 (combined) | 8–15 GB | $0.04–0.08 |
| `java` | 3,000 | 6–10 GB | $0.03–0.05 |
| `py` | 5,000 | 10–18 GB | $0.05–0.09 |
| `js`, `mjs`, `cjs` | 5,000 (combined) | 12–22 GB | $0.06–0.11 |
| `ts`, `tsx` | 5,000 (combined) | 6–10 GB | $0.03–0.05 |
| `go` | 3,000 | 5–9 GB | $0.03–0.05 |
| `rb` | 2,000 | 3–6 GB | $0.02–0.03 |
| `php` | 2,000 | 4–7 GB | $0.02–0.04 |
| `kt`, `kts` | 1,500 | 1–3 GB | $0.005–0.02 |
| `swift` | 1,500 | 2–4 GB | $0.01–0.02 |
| `rs` | 1,500 | 1–3 GB | $0.005–0.02 |
| `sol` | 1,500 | < 1 GB | < $0.01 |
| `dart` | 1,000 | < 2 GB | < $0.01 |

**Always run with `--dry_run` first** to confirm the actual byte count
for your account. Costs above are for cold queries; cached repeats are
free.

## Run

```
# Confirm the cost first.
bq query --dry_run --use_legacy_sql=false \
  --parameter='lang_ext:STRING:py' \
  --parameter='sample_size:INT64:5000' \
  < bench/bigquery-github/query/stratified.sql

# Then run for real, writing NDJSON to disk.
bq query --use_legacy_sql=false --format=prettyjson --max_rows=10000 \
  --parameter='lang_ext:STRING:py' \
  --parameter='sample_size:INT64:5000' \
  < bench/bigquery-github/query/stratified.sql \
  > /tmp/bq-py.json

# Convert prettyjson to NDJSON for the ingester:
node -e "const d=JSON.parse(require('fs').readFileSync('/tmp/bq-py.json','utf8'));for(const r of d){console.log(JSON.stringify(r))}" \
  > /tmp/bq-py.ndjson
```

The result is one JSON object per row with these keys:

```jsonc
{
  "stratum": "random" | "popular" | "recent",
  "repo_name": "owner/repo",
  "path": "src/foo/bar.py",
  "file_id": "abc123...",
  "content": "# the file body\n…",
  "content_size": 12345,
  "repo_license": "apache-2.0"
}
```

Pipe the NDJSON to `bin/run-cycle.mjs --materialize <file>` to write
the source tree under `cycle-<date>/files/`.

## Why we filter on permissive licenses

The BigQuery dataset contains files from a mix of licenses, including
copyleft. The harness scans permissively-licensed code only so the
derived findings can be inspected and discussed without licensing
friction. If you want to broaden the license list, update both
`stratified.sql` and `docs/audit/README.md`.

## Why we filter directory patterns

Vendored directories (`node_modules`, `vendor`, `third_party`, etc.)
inflate per-language file counts with code the author didn't write,
which biases FP-density numbers downward (vendored libraries are
usually older + more reviewed than the host repo's own code). The
ignore list mirrors `scanner/src/runScan.js#DEFAULT_IGNORE`.

## Reproducibility

BigQuery's `bigquery-public-data.github_repos.*` tables are mutable. To
make a cycle reproducible after the fact, the harness writes each
file's `file_id` + a SHA-256 of its content to `manifest.yml`. Two
cycles whose `manifest.yml`s match scanned the same files.
