---
description: Find copy-pasted or bundled third-party code vendored directly into the repo — these never receive security updates and are invisible to dependency scanners.
argument-hint: "[path] [--json]"
---

Detect third-party libraries that have been copied directly into the codebase rather than declared as package manager dependencies. Vendored code is the "dark matter" of supply-chain risk: it carries CVEs indefinitely, is invisible to `npm audit` and OSV scans, and often accumulates for years without anyone noticing. Common forms: minified JS files in `static/`, copied Python modules in `lib/`, a bundled version of jQuery in a `vendor/` directory.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
JSON_OUT=false

for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUT=true ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done
```

After parsing args, scan for vendored code:

1. **Scan for `vendor/` directories and similar patterns:**
   - Any directory named `vendor/`, `vendors/`, `third_party/`, `third-party/`, `thirdparty/`, `extern/`, `external/`, `bundled/`, `embedded/`, `lib/vendor/`, `public/vendor/`, `static/vendor/`, `assets/vendor/`, `www/vendor/`
   - Look for files inside them with `.js`, `.min.js`, `.css`, `.min.css`, `.py`, `.rb`, `.php`, `.go` extensions

2. **Detect minified / bundled libraries by copyright header fingerprint:**
   Read the first 50 lines of every `.js`, `.min.js` file under `PATH_ARG` (excluding `node_modules/`, `dist/`, `build/`, `.git/`). Match against known library copyright patterns:
   - `jQuery` — `@license jquery` or `jQuery v` or `/*! jQuery`
   - `Bootstrap` — `Bootstrap v` or `@license bootstrap`
   - `Lodash` — `Lodash` or `lodash/lodash`
   - `Moment.js` — `moment.js` or `Moment.js`
   - `React` / `ReactDOM` — `react.development.js` or `react.production.min.js` copyright comment
   - `Vue.js` — `Vue.js v` or `@license vue`
   - `Angular` — `@license Angular`
   - `D3.js` — `d3.v` or `Copyright (c) Mike Bostock`
   - `Underscore.js` — `Underscore.js` or `_.js`
   - `Backbone.js` — `Backbone.js`
   - `three.js` — `three.js` or `Three.js`
   - `Chart.js` — `Chart.js`
   - `Highcharts` — `Highcharts`
   - `Prototype.js` — `Prototype JavaScript framework`
   - `MooTools` — `MooTools`
   - Also match any comment containing `@version <semver>` adjacent to a known library name pattern

3. **Detect vendored Python packages:**
   - `.py` files containing `# vendored from`, `# copied from`, `# bundled`, or `# third-party`
   - Directories that contain `__version__ = ` and no corresponding entry in `requirements.txt` or `pyproject.toml`
   - Files matching `*/_vendor/`, `*/vendor/`, `*/vendored/` path patterns

4. **Detect other vendored artifacts:**
   - Font files and icon sets: `font-awesome`, `material-icons`, `glyphicons` (check version in CSS/HTML comments)
   - Embedded SQL scripts from known ORM/DB libraries (check for version comments)
   - PHP files in `vendor/` not managed by `composer.json`

5. **For each detected vendored artifact**, try to determine the version:
   - Extract from copyright comment (e.g., `jQuery v3.1.1`, `Bootstrap v4.0.0`)
   - Fall back to filename (`jquery-3.1.1.min.js`)
   - If version cannot be determined, mark as `(version unknown)`

6. **Cross-reference versions against known CVEs:**
   - Read `last-scan.json` findings for CVE matches on the package name
   - If the version is known, check if it falls within any CVE's affected range
   - Mark as `⛔ VULNERABLE` if CVEs apply, `⚠ UNKNOWN RISK` if version cannot be determined, `✓ NO KNOWN CVE` if current

7. **Print the report:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: vendor-audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scanned 2,341 files  ·  Found 5 vendored artifacts

  ──────────────────────────────────────────────
  ⛔  VULNERABLE
  ──────────────────────────────────────────────
  static/js/jquery.min.js
    Library:  jQuery v1.11.3
    CVE:      CVE-2015-9251  (XSS via cross-domain AJAX)
              CVE-2019-11358 (prototype pollution)
              CVE-2020-11022 (XSS in HTML parsing)
    Fix:      Replace with npm-managed version:
              npm install jquery
              Then load via your bundler instead of a static file.

  vendor/python/requests/
    Library:  requests (version unknown — no version comment found)
    CVE:      Cannot check — version undetermined.
    Fix:      Remove and add `requests` to requirements.txt.
              pip install requests

  ──────────────────────────────────────────────
  ⚠  UNKNOWN RISK (version could not be determined)
  ──────────────────────────────────────────────
  public/js/bootstrap.bundle.js
    Library:  Bootstrap (version unknown)
    Fix:      Check version in file. Latest safe is v5.3.2.
              Replace with: npm install bootstrap

  ──────────────────────────────────────────────
  ✓  NO KNOWN CVE
  ──────────────────────────────────────────────
  static/vendor/moment.min.js       moment v2.29.4     (no active CVE, but deprecated upstream)
  assets/libs/lodash.min.js         Lodash v4.17.21    (no active CVE)

  ──────────────────────────────────────────────
  Summary: 5 vendored artifacts  ·  2 vulnerable  ·  1 unknown  ·  2 clean

  WHY VENDORED CODE IS HIGH RISK
  ──────────────────────────────────────────────
  Vendored files are frozen at the version they were copied. They never
  receive security patches, and no dependency scanner (npm audit, pip-audit,
  osv-scanner) will ever flag them — because they are not registered as
  dependencies. A vendored jQuery from 2015 carries a decade of unpatched
  XSS vulnerabilities with zero visibility.

  GENERAL FIX STRATEGY
  ──────────────────────────────────────────────
  1. Replace vendored files with package-manager-managed versions.
  2. Load them via your bundler (webpack, vite, rollup) rather than
     as static files — this ensures future `npm audit` catches CVEs.
  3. If a file must remain static (e.g., a CDN fallback), pin it to
     the current secure version and add a comment:
       /* vendored: jquery v3.7.1 — update when CVEs are announced */
  4. Add a CI check: grep for known copyright patterns in static/ to
     prevent future vendoring without review.
```

8. If `--json` is passed: emit JSON with fields `{ file, library, version, cves, risk, fix }`.

9. If no vendored code is found:
```
✅  No vendored third-party code detected.
    All dependencies appear to be managed by a package manager.
```

🛡  agentic-security · created by ClearCapabilities.Com
