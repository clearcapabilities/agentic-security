---
description: One-command security router — inspects your project state and tells you the single best next action (scan, fix, launch-check, report-card).
argument-hint: "[path] [--launch]"
---

Smart router for security work. Picks the right next step from project state — vibecoders don't have to choose between `/scan`, `/fix`, `/launch-check`, `/report-card`, `/find-and-fix-everything`.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs secure ${1:-.} ${@:2}
```

## How it decides

| Project state | Recommended action |
|---|---|
| No prior scan | `agentic-security scan .` |
| Critical findings open | `agentic-security fix --finding <id> --preview` |
| High findings open | `/show-findings` |
| Mediums only | `/report-card` |
| All clean | `/security-badge` |
| Last scan > 7 days ago | re-scan |
| `--launch` flag set | `/launch-check` (or block if criticals) |

## Flags

- `--launch` — pre-deploy intent. Blocks if any critical finding open.
- `--json` — emit decision as JSON for piping.
- `--run` — auto-execute the recommended `agentic-security ...` command.

🛡  agentic-security · created by ClearCapabilities.Com
