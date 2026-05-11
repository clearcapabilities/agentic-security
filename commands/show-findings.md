---
description: Triage findings for false positives, then generate an interactive HTML report and open it in the default browser.
argument-hint: "[path]"
---

Triage findings from `.agentic-security/last-scan.json` for false positives, suppress confirmed FPs, then render a self-contained HTML report.

## Step 1 — Triage (automatic before every report)

Read `.agentic-security/last-scan.json` and validate each finding for false positives.

For each finding:
1. Read the file at the reported path and extract ±20 lines around the flagged line.
2. Evaluate whether it is a **true positive**:
   - **True positive**: user-controlled input demonstrably reaches the sink without validation — keep it.
   - **False positive**: the value is validated against an allowlist / switch / explicit enum before the sink; the sink is a safe API overload (e.g. `execFile` with an array, parameterized query); the finding is in a test fixture or mock; or the "source" is an internal constant rather than external input.
3. For each confirmed false positive, add a suppression to `.agentic-security/rules.yml`:

```yaml
suppressions:
  - rule: "<vuln name from finding>"
    files: ["<file path>"]
    reason: "<one sentence: why this is a FP>"
```

Do not suppress anything you are not certain is a false positive. When in doubt, mark it TP.

Print a brief triage summary before generating the report:

```
Triage: N findings reviewed — X true positives, Y suppressed as false positives
```

## Step 2 — Generate report

Re-run the scan with suppressions applied, then write the HTML report:

```bash
mkdir -p reports
REPORT="reports/findings-$(date +%Y%m%d-%H%M%S).html"
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format html --output "$REPORT"
ec=$?
if [ $ec -le 3 ]; then
  open "$REPORT" 2>/dev/null \
    || xdg-open "$REPORT" 2>/dev/null \
    || echo "Open $REPORT in your browser to view the report."
  exit 0
fi
exit $ec
```

The HTML report is self-contained (no external assets, no network required). It includes severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template. Each run writes a timestamped file to `reports/` so previous reports are preserved.

## How to respond to the user

After the command runs, tell the user:
- How many findings were suppressed as FPs (if any)
- That the report was written to `reports/findings-<timestamp>.html`

If it didn't auto-open, give them the platform-specific open command:

- macOS: `open reports/findings-<timestamp>.html`
- Linux: `xdg-open reports/findings-<timestamp>.html`
- Windows: `start reports/findings-<timestamp>.html`

Don't list individual findings inline — the whole point is the HTML view.

🛡  agentic-security · created by ClearCapabilities.Com
