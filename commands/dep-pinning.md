---
description: Audit dependency manifests for loose version ranges that allow silent supply-chain injection — flags unpinned deps and missing lockfiles across all ecosystems.
argument-hint: "[path] [--fix] [--json]"
---

Check every dependency manifest for loose version ranges (`^`, `~`, `>=`, `*`, or no constraint). Unpinned ranges silently pull in new versions on the next install — the exact mechanism used in most supply-chain poisoning attacks. A compromised patch release gets automatically adopted by every project that wrote `^1.0.0` instead of `1.0.1`.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
FIX=false
JSON_OUT=false

for arg in "$@"; do
  case "$arg" in
    --fix)  FIX=true ;;
    --json) JSON_OUT=true ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done
```

After parsing args, perform the audit:

1. **Locate manifests** under `PATH_ARG` (skip `node_modules/`, `vendor/`, `.venv/`):
   - `package.json` — npm/yarn/pnpm (check `dependencies`, `devDependencies`, `optionalDependencies`)
   - `requirements.txt`, `requirements/*.txt` — pip
   - `pyproject.toml` — pip (check `[project.dependencies]` and `[project.optional-dependencies]`)
   - `setup.cfg` — pip (`[options] install_requires`)
   - `Cargo.toml` — cargo (`[dependencies]`, `[dev-dependencies]`)
   - `Gemfile` — bundler
   - `composer.json` — packagist (`require`, `require-dev`)
   - `go.mod` — Go modules (pseudo-versions and floating `master`/`main` are flagged)
   - `pubspec.yaml` — pub.dev

2. **For each dependency**, classify the version constraint:
   - `EXACT` — `1.2.3`, `==1.2.3`, `=1.2.3` — pinned, safe
   - `PATCH` — `~1.2.3`, `~=1.2.3` (pip), `1.2.*` — allows patch updates only; low risk if lockfile present
   - `MINOR` — `^1.2.3`, `>=1.2.0,<2.0.0` — allows minor + patch updates; medium risk
   - `MAJOR` — `>=1.0.0`, `*`, `""` (empty), `latest` — allows any version; high risk
   - `FLOATING` — git dependency without a pinned sha/tag (`git+https://…` with no `#sha`) — high risk
   - `MISSING` — no version constraint at all (bare package name)

3. **Check for lockfile presence** per manifest:
   - `package.json` → `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
   - `requirements.txt` → `requirements.lock` or `pip.lock` (uncommon; note absence)
   - `Cargo.toml` → `Cargo.lock`
   - `Gemfile` → `Gemfile.lock`
   - `composer.json` → `composer.lock`
   - `go.mod` → `go.sum`
   - `pubspec.yaml` → `pubspec.lock`
   - A lockfile reduces the risk of range-based deps for reproducible installs, but does NOT protect against a lockfile that was committed with a poisoned version. Note both.

4. **Print the report:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: dep-pinning
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Scanned 3 manifests · 94 total dependencies
  Lockfiles present: package-lock.json ✓  Cargo.lock ✓  (no pip.lock)

  UNPINNED DEPENDENCIES
  ──────────────────────────────────────────────

  HIGH — allows any version (wildcard / floating)
    package.json
      some-lib       "*"          → pin to "2.1.4"
      other-pkg      "latest"     → pin to "1.0.0"

  MEDIUM — allows minor + patch updates (^)
    package.json
      express        "^4.18.0"    → current resolved: 4.18.2  → pin to "4.18.2"
      lodash         "^4.17.20"   → current resolved: 4.17.21 → pin to "4.17.21"
      axios          "^1.4.0"     → current resolved: 1.6.2   → pin to "1.6.2"

    requirements.txt
      requests       ">=2.28.0"   → current: 2.31.0  → pin to "==2.31.0"
      flask          ">=2.0"      → current: 3.0.0   → pin to "==3.0.0"

  LOW — allows patch updates only (~)
    package.json
      dotenv         "~16.0.0"    → current resolved: 16.0.3 → pin to "16.0.3"

  NO LOCKFILE — pip (requirements.txt)
  ──────────────────────────────────────────────
  ⚠  No lockfile found for requirements.txt. Every `pip install` may resolve
     to different versions. Consider pip-compile (pip-tools) or Poetry to
     generate a deterministic lockfile.

  ──────────────────────────────────────────────
  Summary: 10 unpinned  (2 high · 7 medium · 1 low)  across 3 manifests
```

5. After the table, print a **pinning strategy recommendation** tailored to the ecosystems found:
   - **npm:** "Run `npm shrinkwrap` or commit `package-lock.json`. Replace `^` ranges with exact versions using: `npm install --save-exact <pkg>`."
   - **pip:** "Use `pip-compile` (from pip-tools) to generate `requirements.lock`. Or switch to Poetry which pins by default in `poetry.lock`."
   - **cargo:** "Cargo.lock is already committed — you're protected for binary builds. For libraries, `~` ranges are conventional and acceptable."
   - **bundler:** "Run `bundle lock --add-platform` after pinning. Commit `Gemfile.lock`."

6. If `--fix` is passed: for each `MINOR` or `PATCH` dep, look up the currently resolved version from the lockfile (or `node_modules/<pkg>/package.json`) and rewrite the manifest to use that exact version. Print a diff of all changes made. Do not modify `HIGH`/`FLOATING` deps automatically — those require human review.

7. If `--json` is passed: emit JSON with fields `{ manifest, package, constraint, risk, resolved_version, pinned_equivalent }`.

8. If all dependencies are pinned:
```
✅  All N dependencies across M manifests are pinned to exact versions.
```

🛡  agentic-security · created by ClearCapabilities.Com
