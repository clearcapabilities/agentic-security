---
description: Score how stale your direct dependencies are across all ecosystems — stale deps are the primary CVE accumulation vector.
argument-hint: "[path] [--json] [--ecosystem npm|pip|cargo|gem|pub|packagist]"
---

Check every direct dependency against its registry to determine how far behind the latest version it is. Stale dependencies accumulate unpatched CVEs over time: a package that was safe when pinned may have had several security releases since. This command makes staleness visible so you can prioritize which deps to update.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
JSON_OUT=false
ECOSYSTEM_FILTER=""

for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUT=true ;;
    --ecosystem) ;;
    npm|pip|cargo|gem|pub|packagist) ECOSYSTEM_FILTER="$arg" ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json \
  --output .agentic-security/last-scan.json
```

After the scan completes:

1. Read `components` from `.agentic-security/last-scan.json`. Filter to direct deps only (same logic as `/trim-dependencies` step 3). If `--ecosystem` is set, filter to that ecosystem only.

2. **For each direct dep, determine version currency** using registry APIs (same endpoints as the SCA scanner's `queryRegistries()`):
   - **npm:** `https://registry.npmjs.org/<name>` → `dist-tags.latest`
   - **PyPI:** `https://pypi.org/pypi/<name>/json` → `info.version`
   - **crates.io:** `https://crates.io/api/v1/crates/<name>` → `crate.newest_version`
   - **RubyGems:** `https://rubygems.org/api/v1/gems/<name>.json` → `version`
   - **pub.dev:** `https://pub.dev/api/packages/<name>` → `latest.version`
   - **Packagist:** `https://packagist.org/packages/<name>.json` → latest stable version key
   - **Maven:** `https://search.maven.org/solrsearch/select?q=g:"<group>"+AND+a:"<name>"&rows=1&wt=json` → `docs[0].latestVersion`
   - **Go modules:** `https://proxy.golang.org/<module>/@latest` → `Version`

3. **Parse and compare semver** (installed vs latest) to produce a staleness tier:
   - `CURRENT` — installed version equals latest (or latest is a prerelease/rc and installed is the latest stable)
   - `PATCH` — behind by patch releases only (e.g., `1.2.3` → `1.2.9`); security fixes often ship as patches
   - `MINOR` — behind by one or more minor versions (e.g., `1.2.x` → `1.5.x`); likely missing feature-level security fixes
   - `MAJOR` — behind by one or more major versions (e.g., `1.x` → `3.x`); almost certainly missing security patches, possibly EOL
   - `EOL` — installed version is in a known end-of-life branch (cross-reference with `last-scan.json` deprecated findings)

4. **Cross-reference with CVE data** from `last-scan.json`:
   - For each stale dep, count how many CVE findings apply to the installed version
   - Note if the latest version resolves any of those CVEs

5. **Print the report**, sorted by staleness tier (MAJOR → MINOR → PATCH → CURRENT):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: dep-freshness
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Checked 42 direct dependencies across 3 ecosystems.

  MAJOR VERSION BEHIND  (update recommended — likely EOL or missing security releases)
  ──────────────────────────────────────────────
  ⛔  express          1.8.3   →  4.18.2   (+3 major)   [package.json]
      2 CVEs in installed version. Latest resolves both.
      npm install express@latest

  ⛔  django           2.2.28  →  4.2.13   (+2 major, EOL)  [requirements.txt]
      Django 2.2 reached end-of-life April 2022. No further security patches.
      3 CVEs in installed version.
      pip install "django>=4.2"

  ⛔  log4j-core       2.14.1  →  2.23.1   (Log4Shell era — +9 patches)  [pom.xml]
      CVE-2021-44228 (Log4Shell, CVSS 10.0) in installed version.
      Latest resolves Log4Shell and 8 subsequent CVEs.
      Update <version>2.23.1</version> in pom.xml

  MINOR VERSION BEHIND
  ──────────────────────────────────────────────
  ⚠   axios            1.4.0   →  1.6.8    (+2 minor)   [package.json]
      1 CVE (SSRF) fixed in 1.6.0.
      npm install axios@latest

  ⚠   pillow           9.0.0   →  10.3.0   (+1 major, +3 minor)  [requirements.txt]
      4 CVEs fixed since 9.0.0 (image parsing, DoS).
      pip install --upgrade pillow

  PATCH BEHIND  (consider updating — security fixes ship as patches)
  ──────────────────────────────────────────────
  •   lodash           4.17.20  →  4.17.21  [package.json]   0 CVEs in gap
  •   requests         2.30.0   →  2.31.0   [requirements.txt]  0 CVEs in gap
  •   serde            1.0.180  →  1.0.197  [Cargo.toml]     0 CVEs in gap

  CURRENT  (28 packages)
  ──────────────────────────────────────────────
  ✓  28 packages are at the latest version.

  ──────────────────────────────────────────────
  Summary: 42 deps checked
    3 major behind  (2 with active CVEs resolved in latest)
    2 minor behind  (2 with active CVEs resolved in latest)
    3 patch behind  (0 with CVEs in gap)
    28 current

  CVEs resolvable by updating: 7
```

6. After the table, print an **update priority guide**:
   - "Update MAJOR-behind deps first — especially any marked EOL. Security patches stop being backported when a branch ends support."
   - "Prioritize deps where the CVE count drops to zero in the latest version — these are the highest-ROI updates."
   - "PATCH-behind deps are lower urgency unless the patch release notes mention security fixes."

7. If `--json` is passed: emit a JSON array with fields `{ ecosystem, name, version, latest, tier, cve_count, cves_resolved_in_latest, manifest }`.

8. If all dependencies are current:
```
✅  All N direct dependencies are at the latest version.
```

🛡  agentic-security · created by ClearCapabilities.Com
