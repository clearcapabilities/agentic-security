---
description: Identify heavy or high-risk dependencies that have lighter-weight, native, or more actively maintained alternatives — shrinks attack surface without losing functionality.
argument-hint: "[path] [--json]"
---

Match your installed dependencies against a curated catalog of packages that have well-established safer or lighter alternatives. Each substitution removes one or more packages from your supply chain entirely — reducing CVE exposure, install-time attack surface, and bundle size. The catalog covers packages where a native browser/runtime API, a purpose-built successor, or a significantly smaller library covers the same use case.

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

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json \
  --output .agentic-security/last-scan.json
```

After the scan completes, read `components` from `last-scan.json` and match against the following catalog. For each match found in the project, print a finding.

**Substitution catalog** (check installed package name against each entry):

```
NATIVE REPLACEMENT AVAILABLE — remove the package entirely
──────────────────────────────────────────────────────────
moment / moment-timezone
  → Use: native Intl.DateTimeFormat, Intl.RelativeTimeFormat, Date
  → Or:  date-fns (modular, tree-shakeable, 0 dependencies)
  → Why: moment is officially deprecated by its authors; ships 290KB
         minified; native Intl covers 95% of use cases in Node 12+.

request / superagent / got@<12
  → Use: native fetch (Node 18+, all modern browsers)
  → Or:  got@13 (ESM-only, maintained, lightweight)
  → Or:  ky (browser/node, fetch-based, 2.4KB gzipped)
  → Why: `request` is deprecated and unmaintained since 2020.
         native fetch ships with Node 18+, no supply chain required.

bluebird / q / when
  → Use: native Promise, async/await
  → Why: native Promises are built into every modern JS runtime.
         bluebird and q are unmaintained; zero supply-chain benefit.

uuid (v1–v4) / shortid / nanoid (for non-security IDs)
  → Use: crypto.randomUUID() (Node 15.6+, all modern browsers)
  → Or:  nanoid for URL-safe short IDs (if crypto.randomUUID() isn't enough)
  → Why: crypto.randomUUID() is CSPRNG-backed, built-in, zero dependency.

node-fetch (v2)
  → Use: native fetch (Node 18+) or node-fetch@3 (ESM)
  → Why: node-fetch v2 has known CVEs; v3 requires ESM.

mkdirp / make-dir
  → Use: fs.mkdirSync(path, { recursive: true }) (Node 10.12+)
  → Why: Built-in since Node 10.12. No supply chain needed.

rimraf (v3)
  → Use: fs.rmSync(path, { recursive: true, force: true }) (Node 14.14+)
  → Or:  rimraf@5 (ESM, maintained)
  → Why: rimraf v3 depends on glob@7 which has known deprecations.

path-to-regexp (old versions in express < 5)
  → Note: Ensure express is updated to v5 which ships path-to-regexp@8.
  → Why: CVE-2024-45296 (ReDoS) in path-to-regexp < 0.1.10 / < 8.0.0

querystring (built-in, deprecated)
  → Use: URLSearchParams (built-in, Web API)
  → Why: Node's `querystring` module is deprecated since Node 14.

colors / chalk@4 (commonjs)
  → Use: chalk@5 (ESM, maintained)
  → Or:  kleur (tiny, 2KB, no supply-chain incidents)
  → Or:  picocolors (2.6KB, zero deps, fastest)
  → Why: colors had a supply-chain sabotage incident (Jan 2022).

LIGHTER ALTERNATIVE — same functionality, fewer deps, smaller surface
──────────────────────────────────────────────────────────────────────
lodash / underscore
  → Use: native ES2020+ array/object methods (map, filter, reduce,
         Object.entries, Object.fromEntries, structuredClone, etc.)
  → Or:  lodash-es (ESM, tree-shakeable — import only what you use)
  → Or:  just-* (individual micro-libraries, zero cross-deps)
  → Why: lodash ships 71KB (minified). Most projects use 3–5 functions.
         Native methods cover >80% of lodash use cases.

axios (if only used for simple HTTP calls)
  → Use: native fetch with a thin wrapper (ky or wretch)
  → Or:  keep axios if you need interceptors, request cancellation, or
         automatic JSON transforms — it's well-maintained for that use case.
  → Why: native fetch covers simple GET/POST; axios adds 22KB and deps.

express (for simple API servers)
  → Consider: hono (ultra-fast, 12KB, Web API compatible, edge-ready)
  → Consider: fastify (faster than express, built-in schema validation)
  → Note: only switch if your express usage is simple — express is fine
          for large apps with many middleware.

bcryptjs (pure JS bcrypt)
  → Use: bcrypt (native binding — faster)
  → Or:  argon2 (stronger algorithm, recommended for new projects)
  → Note: bcryptjs is safe; argon2 is the OWASP-recommended modern choice.

crypto-js
  → Use: native Web Crypto API (SubtleCrypto)
  → Why: Web Crypto is FIPS-compliant, hardware-accelerated, built-in.
         crypto-js is pure JS — slower and a larger attack surface.

node-uuid (deprecated package name)
  → Use: uuid (the correct package name) or crypto.randomUUID()

moment-timezone
  → Use: Intl.DateTimeFormat with timeZone option (built-in since Node 13)

xmlhttprequest / xmlhttprequest-ssl
  → Use: native fetch
  → Why: These are deprecated shims for non-browser XHR.

ACTIVELY MAINTAINED SUCCESSOR — original is abandoned
──────────────────────────────────────────────────────
request             → got, node-fetch@3, or native fetch
node-uuid           → uuid (correct name)
coffee-script       → TypeScript or modern ES2020+
bower               → npm / yarn / pnpm
grunt               → vite, rollup, esbuild, or npm scripts
gulp@3              → gulp@4 or vite
istanbul            → c8 (uses V8 native coverage, zero config)
mocha + chai        → node:test (built-in since Node 18) for simple suites
jshint / jslint     → eslint (with typescript-eslint for TS projects)
optimist / minimist → yargs, commander, or node:parseArgs (Node 18.3+)
```

**Output format:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: dep-alternatives
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Checked 42 packages  ·  5 with better alternatives found

  NATIVE REPLACEMENT AVAILABLE (remove the package entirely)
  ──────────────────────────────────────────────
  moment @ 2.29.4    [package.json · 290 KB · deprecated upstream]
    Replace with native Intl.DateTimeFormat or date-fns.
    moment is officially deprecated by its authors. Example migration:
      Before: moment(date).format('YYYY-MM-DD')
      After:  new Intl.DateTimeFormat('en-CA').format(date)   // → "2024-01-15"
    Removing moment also removes: moment-timezone (+3 transitive packages)

  uuid @ 8.3.2       [package.json]
    Replace with: crypto.randomUUID()  (Node 15.6+, no import required)
      Before: import { v4 as uuidv4 } from 'uuid'; uuidv4()
      After:  crypto.randomUUID()
    Removing uuid saves 1 package from your supply chain.

  LIGHTER ALTERNATIVE
  ──────────────────────────────────────────────
  lodash @ 4.17.21   [package.json · 71 KB minified]
    3 lodash functions detected in source: _.pick, _.merge, _.cloneDeep
    Native equivalents:
      _.pick(obj, keys)    → Object.fromEntries(keys.map(k => [k, obj[k]]))
      _.merge(a, b)        → { ...a, ...b }  or structuredClone + assign
      _.cloneDeep(obj)     → structuredClone(obj)  (Node 17+)
    Or: switch to lodash-es and import only: import { pick } from 'lodash-es'
    Removing lodash would save 71 KB and 1 package.

  axios @ 1.4.0      [package.json]
    Source uses axios for 2 GET requests and 1 POST. No interceptors detected.
    Replacement (native fetch):
      const res = await fetch(url);
      const data = await res.json();
    Keep axios if you need request interceptors, timeout config, or
    automatic request cancellation.

  ACTIVELY MAINTAINED SUCCESSOR
  ──────────────────────────────────────────────
  colors @ 1.4.0     [package.json]
    Successor: chalk@5 or picocolors
    colors had a supply-chain sabotage incident in January 2022.
    npm install picocolors && npm uninstall colors
    Migration: picocolors.green('text') vs colors.green('text')  (same API shape)

  ──────────────────────────────────────────────
  Summary: 5 packages with better alternatives  ·  2 removable via native APIs
  Removing all 5 would save approximately 365 KB and 5 packages from your
  supply chain, eliminating 1 package with a supply-chain incident history.
```

For each match, detect which functions/methods from that package are actually used in source (by grepping for `<pkg>.`, `from '<pkg>'` imports, and common method names) and tailor the migration example to what's actually used in the project. If usage is too broad to suggest a simple migration, say so and recommend a phased approach.

If `--json` is passed: emit JSON with fields `{ package, version, category, alternative, reason, estimated_savings_kb, migration_example }`.

If no matches found:
```
✅  No high-priority substitution candidates found in your 42 dependencies.
```

🛡  agentic-security · created by ClearCapabilities.Com
