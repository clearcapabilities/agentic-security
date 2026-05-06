---
description: Save current findings as a baseline, or diff the current scan against the saved baseline.
argument-hint: "save|diff [path]"
---

Manage the security baseline so /security-scan can highlight only NEW findings.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/bin/agentic-security.js baseline ${1} ${2:-.}
```

- `save` — copy `.agentic-security/last-scan.json` to `.agentic-security/baseline.json`. Run after the codebase has been triaged and acknowledged findings have been accepted.
- `diff` — re-scan and compare against the baseline. Reports findings added (regressions) and findings fixed.

The pre-commit hook (`PreToolUse` on `git commit`) compares against this baseline and blocks commits that introduce critical findings unless `AGENTIC_SECURITY_BYPASS=1` is set.
