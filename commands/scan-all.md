---
description: One-screen verdict — "safe to deploy?" — and if not, asks which severity tier to fix. The vibecoder default.
argument-hint: "[path]"
---

Run the agentic-security scanner against `${1:-.}` and render the one-screen
verdict. This is the vibecoder default: high-confidence findings only, no
CWE/CVSS jargon.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs ship ${1:-.}; ec=$?; [ $ec -le 3 ] && exit 0 || exit $ec
```

## How to respond to the user

The scanner's output already includes the right call-to-action. After it
runs, **do not list individual findings.** Instead:

- If the verdict is ✅: tell the user they're safe to deploy, in one short line.
- If the verdict is ❌: relay the four-option prompt the scanner printed and
  **ask which set the user wants to fix:**
    1. Critical only
    2. Critical + High
    3. Critical + High + Medium
    4. All

  Wait for their answer before doing anything else.

Map the answer to `/fix-all` and run it:

| Answer | Command |
|---|---|
| 1 (Critical only)              | `/fix-all --severity critical` |
| 2 (Critical + High)            | `/fix-all --severity high`     |
| 3 (Critical + High + Medium)   | `/fix-all --severity medium`   |
| 4 (All)                        | `/fix-all --severity low`      |

If they ask to see specifics first, run `/security-scan-all --firehose` for
the full per-finding list. Don't volunteer that list unprompted — the whole
point of `/scan-all` is the one-screen summary.

🛡  agentic-security · created by ClearCapabilities.Com
