---
description: Find and remove installed dependencies that are never imported in source code — reduces attack surface and package bloat.
argument-hint: "[path] [--dry-run] [--include-dev] [--apply]"
---

Identify installed packages that are never imported anywhere in source code, measure their on-disk footprint, surface any CVEs they carry, and generate removal commands.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
DRY_RUN=false
INCLUDE_DEV=false
APPLY=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)     DRY_RUN=true ;;
    --include-dev) INCLUDE_DEV=true ;;
    --apply)       APPLY=true ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json \
  --output .agentic-security/last-scan.json
```

After the scan completes:

1. Read `.agentic-security/last-scan.json` and extract:
   - `components` — every installed package (`name`, `version`, `ecosystem`, `scope`, `filePath`)
   - `findings` — use to cross-reference known CVEs per package

2. Build the **imported set** by scanning source files under `PATH_ARG`:
   - **JS/TS:** match `require('pkg')`, `import … from 'pkg'`, `import 'pkg'`, dynamic `import('pkg')` — keep the bare package name (e.g. `express` from `express/router`; scoped packages like `@aws-sdk/client-s3` stay as-is).
   - **Python:** match `import pkg`, `from pkg import …` — keep the top-level module name.
   - **Ruby:** match `require 'pkg'`, `gem 'pkg'`.
   - **Rust:** match `use pkg::`, `extern crate pkg` — correlate to `Cargo.toml` dep names.
   - Skip `node_modules/`, `vendor/`, `dist/`, `build/`, `.venv/`, `__pycache__/`, `.git/`.
   - Normalize all names to lowercase. Record total source files scanned.

3. Determine which packages are **direct** (safe to remove):
   - **npm/yarn/pnpm:** `dependencies` and (if `--include-dev`) `devDependencies` in `package.json` under `PATH_ARG`.
   - **pip:** packages listed in `requirements.txt`, `requirements/*.txt`, `pyproject.toml [project.dependencies]`, `setup.cfg [options] install_requires`.
   - **cargo:** `[dependencies]` (and `[dev-dependencies]` if `--include-dev`) in `Cargo.toml`.
   - **bundler:** packages in `Gemfile` (non-group or `--include-dev` for dev groups).
   - Transitive-only deps must be skipped — the package manager removes them automatically.

4. Apply **safe-to-skip** exclusions — never flag for removal:
   - `@types/*` packages (TypeScript declarations — no import needed)
   - Packages referenced in `package.json` `"scripts"` values (CLI tools: `eslint`, `jest`, `ts-node`, `rimraf`, etc.)
   - Packages listed in `peerDependencies` or `peerDependenciesMeta`
   - Packages whose name ends in `-loader`, `-plugin`, `-preset`, `-transform` (webpack/babel tooling)
   - `dotenv` when a `.env` file exists (loaded via `--require` flag, not an import)
   - `source-map-support`, `reflect-metadata`, `tsconfig-paths` (runtime bootstrappers)
   - Packages explicitly marked `# trim-dependencies-keep: pkg` anywhere in the project

5. **Compute the bloat list:**
   ```
   bloat = direct_deps ∩ NOT(imported) ∩ NOT(safe_to_skip)
   ```

6. **Enrich each bloat package** before printing:
   a. **On-disk size:** `du -sk node_modules/<pkg>/` for npm; `pip show <pkg>` + size of install dir for pip. Mark `(size unknown)` if `node_modules/` is absent.
   b. **Transitive count:** entries in the lockfile that exist only because of this package. For npm: walk `package-lock.json` `packages` deps recursively.
   c. **CVE count:** count findings in `last-scan.json` where `packageName === pkg.name`. Label `⚠` if any.
   d. **Package purpose:** read `description` from `node_modules/<pkg>/package.json` (npm) or `pip show` Summary field. Fall back to a one-line description derived from the package name.
   e. **Deprecation flag:** if the package appeared as deprecated in the scan output, note it.
   f. **Security history note:** flag packages with known supply-chain incidents (malicious releases, self-sabotage history).

7. **Print the report:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: trim-dependencies
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scanned 847 source files across 42 direct packages.
  Imported in source:  38 packages
  Never imported:       4 packages  (9.5% of direct deps)

  Removing these would eliminate:
    • 14.2 MB on disk
    • 31 transitive packages from your dependency tree
    • 2 packages with known CVEs currently in your supply chain

  REMOVABLE PACKAGES
  ──────────────────────────────────────────────
  npm (package.json)

  ⚠  lodash @ 4.17.21   [5.8 MB · +0 transitive · 1 CVE]
     Utility library for arrays, objects, and strings.
     Why removable: 0 import/require statements found across 847 source files.
     Security impact: Removing eliminates CVE-2021-23337 (command injection
     via template functions) from your supply chain entirely.
     Remove: npm uninstall lodash

  •  moment @ 2.29.4    [4.7 MB · +3 transitive · deprecated upstream]
     Parse, validate, and display dates.
     Why removable: 0 import statements found. The moment authors officially
     deprecated this package in 2020 — no new features or security patches.
     Security impact: Removes 3 transitive packages (moment-timezone, locale
     files) and an unmaintained library from your attack surface.
     Remove: npm uninstall moment

  •  colors @ 1.4.0     [76 KB · +0 transitive · supply-chain incident]
     ANSI color strings for terminal output.
     Why removable: 0 import statements found.
     Security note: This package sabotaged its own users in January 2022 by
     shipping an infinite loop in a patch release. Low trust, no active
     maintainer.
     Remove: npm uninstall colors

  pip (requirements.txt)

  ⚠  boto3 @ 1.26.0    [3.6 MB · +28 transitive · 1 CVE]
     AWS SDK for Python — S3, Lambda, DynamoDB, and 300+ service clients.
     Why removable: 0 import statements found in .py source files.
     Security impact: Removing eliminates 28 transitive AWS SDK packages
     (botocore, s3transfer, urllib3, jmespath…) and CVE-2023-34241 from your
     dependency tree.
     Remove: pip uninstall -y boto3

  ──────────────────────────────────────────────
  Summary: 4 packages removable · 14.2 MB · 31 transitive deps · 2 CVEs eliminated

  REMOVAL COMMANDS (copy-paste ready)
  ──────────────────────────────────────────────

  # npm
  npm uninstall lodash moment colors

  # pip
  pip uninstall -y boto3

  Run with --apply to execute these commands automatically.

  ──────────────────────────────────────────────
  SKIPPED (safe-to-keep)
    @types/node, jest, eslint  — CLI tools / type declarations
    webpack-dev-server         — referenced in npm scripts
```

8. After the per-package table, print a one-paragraph **"What this means for your security posture"** summary. Cover: total CVEs removed from supply chain, reduction in transitive dep count, whether any removed packages were deprecated or had supply-chain incidents, and a sentence on the ongoing risk of keeping dead code in the manifest.

9. **Dry-run vs apply:**
   - Default (no flag): print the report and removal commands. Do not execute anything.
   - `--apply`: warn that this will modify manifests, list the packages about to be removed, and ask for confirmation. On confirmation, run each removal command, then re-run the scan and confirm the package count shrank. Warn if any tests fail after removal.

10. If zero bloat packages are found:
```
✅  No unimported direct dependencies found — nothing to trim.
    (Scanned N source files across M direct packages)
```

🛡  agentic-security · created by ClearCapabilities.Com
