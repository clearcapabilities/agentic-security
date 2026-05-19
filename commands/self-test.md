---
description: Adversarial self-test (FR-LEARN-8) — the scanner attacks itself. Mutates known-vuln fixtures with renaming / wrapping / API-swap strategies, runs the scanner against each variant, surfaces detector gaps.
argument-hint: "[--fixtures <dir>] [--output <file>]"
---

Run the closed-loop self-test. Useful before releasing a new rule pack: every escape is a rule gap that should become a regression fixture.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
FIXTURES="scanner/test/fixtures"
OUTPUT="self-test-results.json"
NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    fixtures) FIXTURES="$arg"; NEXT="" ; continue ;;
    output) OUTPUT="$arg"; NEXT="" ; continue ;;
  esac
  case "$arg" in
    --fixtures) NEXT="fixtures" ;;
    --output) NEXT="output" ;;
  esac
done

if [ ! -d "${CLAUDE_PLUGIN_ROOT}/${FIXTURES}" ] && [ ! -d "$FIXTURES" ]; then
  echo "Fixtures directory not found: $FIXTURES"
  echo "Default looks under scanner/test/fixtures relative to the plugin root."
  exit 1
fi

cd "${CLAUDE_PLUGIN_ROOT}" 2>/dev/null || true

node scripts/self-test-runner.mjs --fixtures "$FIXTURES" --output "$OUTPUT"
ec=$?

# Exit 0 if all mutations caught; exit 1 means escapes detected (informational).
if [ $ec -eq 0 ]; then
  echo ""
  echo "✅  No detector gaps — every mutation strategy was caught."
elif [ $ec -eq 1 ]; then
  echo ""
  echo "❌  Detector gaps detected. See $OUTPUT for the full mutation matrix."
  echo "    Each gap should become a regression fixture + a strengthened rule."
fi
exit 0
```

## Mutation strategies

Per family the runner applies a curated mutation set:

| Family | Mutations |
|---|---|
| sql-injection | identifier obfuscation, template-literal wrap, helper extraction |
| command-injection | `exec`→`execSync`→`spawn`, fake-sanitizer wrap |
| xss | `innerHTML`→`outerHTML`→`insertAdjacentHTML`→`document.write` |
| ssrf | `fetch`→`axios`→`got`→`node-fetch` |
| path-traversal | introduce no-op `path.normalize` |
| prototype-pollution | `__proto__`→`["__proto__"]`→`["__pro" + "to__"]` |

## CI usage

Run as a pre-release CI gate. The exit code is 0 (all caught) or 1 (escapes). Pair with `/detector-fuzz` for a more aggressive bench-shape fuzzer with a per-family escape-rate threshold.

🛡  agentic-security · created by ClearCapabilities.Com
