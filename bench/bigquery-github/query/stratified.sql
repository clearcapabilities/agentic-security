-- Stratified per-language sample of source files from
-- bigquery-public-data.github_repos. Run with `bq query --format=json`
-- (per query/README.md) and pipe the output to ingest/materialize.mjs.
--
-- Parameters (set via `--parameter` flags or template substitution):
--   @lang_ext   STRING  — file extension WITHOUT the leading dot ("py", "cs", "cpp", …)
--   @sample_size INT64  — files to return for this language (e.g. 5000)
--
-- Cost: typical query reads ~5–20 GB depending on @lang_ext (file
-- distribution by language is uneven). Estimate before running with
-- `bq query --dry_run`. See query/README.md for a per-language table.
--
-- Stratification: three strata blended in roughly equal proportions —
--   1. RANDOM   — uniform sample across the dataset.
--   2. POPULAR  — repos by watch_count desc (top-of-distribution).
--   3. RECENT   — repos by max-committer-date desc (current idioms).
--
-- The harness must NOT publish per-repo findings derived from this
-- query. cycle-<date>/ is gitignored.

WITH eligible_files AS (
  SELECT
    f.repo_name,
    f.path,
    f.id AS file_id,
    -- watch_count drives the POPULAR stratum
    COALESCE(s.watch_count, 0) AS watch_count,
    -- max committer date drives the RECENT stratum
    COALESCE(c.max_committer_date, TIMESTAMP("1970-01-01")) AS max_committer_date
  FROM `bigquery-public-data.github_repos.files` AS f
  LEFT JOIN `bigquery-public-data.github_repos.sample_repos` AS s
    ON s.repo_name = f.repo_name
  LEFT JOIN (
    SELECT repo_name, MAX(committer.date) AS max_committer_date
    FROM `bigquery-public-data.github_repos.sample_commits`
    GROUP BY repo_name
  ) AS c ON c.repo_name = f.repo_name
  WHERE
    -- File-extension filter — keyed off @lang_ext.
    LOWER(f.path) LIKE CONCAT('%.', @lang_ext)
    -- Skip directories that are usually vendored, generated, or test scaffolding.
    AND NOT REGEXP_CONTAINS(LOWER(f.path),
        r'(^|/)(node_modules|vendor|third_party|3rd_party|dist|build|target|bin|obj|out|coverage|\.git|\.gradle|__pycache__|\.venv|venv|env|tests?|__tests__|spec|mocks?)(/|$)')
    -- File-size budget (~500 KB raw; the engine skips larger files anyway).
    AND f.size BETWEEN 200 AND 500000
),

random_stratum AS (
  SELECT repo_name, path, file_id, 'random' AS stratum
  FROM eligible_files
  ORDER BY FARM_FINGERPRINT(CONCAT(repo_name, path))
  LIMIT CAST(CEIL(@sample_size / 3.0) AS INT64)
),

popular_stratum AS (
  SELECT repo_name, path, file_id, 'popular' AS stratum
  FROM eligible_files
  WHERE watch_count > 0
  ORDER BY watch_count DESC, FARM_FINGERPRINT(CONCAT(repo_name, path))
  LIMIT CAST(CEIL(@sample_size / 3.0) AS INT64)
),

recent_stratum AS (
  SELECT repo_name, path, file_id, 'recent' AS stratum
  FROM eligible_files
  WHERE max_committer_date > TIMESTAMP("2023-01-01")
  ORDER BY max_committer_date DESC, FARM_FINGERPRINT(CONCAT(repo_name, path))
  LIMIT CAST(CEIL(@sample_size / 3.0) AS INT64)
),

sampled_files AS (
  SELECT * FROM random_stratum
  UNION ALL SELECT * FROM popular_stratum
  UNION ALL SELECT * FROM recent_stratum
)

-- Join the file content. `github_repos.contents` is keyed by file id.
-- Skip binaries and anything the content table marked as a sample miss.
SELECT
  sf.stratum,
  sf.repo_name,
  sf.path,
  sf.file_id,
  c.content,
  c.size AS content_size,
  -- License declaration from the repo-level table (when present). The harness
  -- filters to known permissive licenses before materializing files.
  l.license AS repo_license
FROM sampled_files AS sf
JOIN `bigquery-public-data.github_repos.contents` AS c
  ON c.id = sf.file_id
LEFT JOIN `bigquery-public-data.github_repos.licenses` AS l
  ON l.repo_name = sf.repo_name
WHERE
  c.binary IS NOT TRUE
  AND c.content IS NOT NULL
  AND LENGTH(c.content) > 0
  -- Keep only permissive licenses. Add more if you have legal sign-off.
  AND l.license IN ('mit', 'apache-2.0', 'bsd-2-clause', 'bsd-3-clause', 'isc', 'unlicense', 'cc0-1.0')
;
