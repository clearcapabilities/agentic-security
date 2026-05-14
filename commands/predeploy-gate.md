---
description: Block production deploys (vercel --prod, fly deploy, wrangler publish, netlify deploy --prod, railway up) when critical findings or KEV-listed dependencies are present. Vibe-coders skip CI gates; intercept at the deploy command instead — both in Claude's Bash tool (via destructive-guard) AND in their own terminal (via sourced shell wrapper).
argument-hint: "[install | check | status | off]"
---

# Pre-deploy gate

Most CI/CD gates run on `git push`. Vibe-coders don't push to a CI/CD pipeline — they run `vercel --prod` from a terminal. This gate intercepts at the deploy command itself, so the safety net catches them regardless of whether their CI was wired up.

## Two layers of coverage

1. **Inside Claude Code (Bash tool):** the existing `destructive-guard` hook already catches direct-prod deploy commands. Set `/destructive-guard block` to enforce.
2. **Outside Claude Code (your terminal):** source `scripts/predeploy-gate.sh` from your shell profile. The wrapper functions intercept `vercel`, `fly`, `flyctl`, `wrangler`, `netlify`, and `railway` deploy invocations.

## What the gate checks

- `.agentic-security/last-scan.json` exists
- The scan is no older than `require_recent_scan_hours` (default: 24)
- Zero findings at the blocking severity (default: `critical`)
- Zero KEV-listed (known-exploited) dependencies in your tree

If all four pass, the deploy proceeds. If any fail, the command is refused with specific remediation:

```
🚦  agentic-security pre-deploy gate
    Last scan:  Mon May 13 09:00 2026
    Findings:   2 critical · 7 high · 18 medium

    🛑  BLOCKED: 2 critical finding(s). 1 KEV-listed (known-exploited) package(s).

    Options:
      1. Fix the issues:           /find-and-fix-everything
      2. Triage one critical:      /show-findings --severity critical
      3. Override this once:       AS_GATE_OVERRIDE=1 vercel deploy --prod
      4. Loosen the gate:          edit .agentic-security/predeploy-gate.json
```

## Configuration

`.agentic-security/predeploy-gate.json`:

```json
{
  "block_on": ["critical"],
  "block_on_kev": true,
  "require_recent_scan_hours": 24
}
```

Tighter alternative: `"block_on": ["critical", "high"]` blocks on any high-severity finding too.

## Install the shell wrapper

Add this to your `~/.bashrc` / `~/.zshrc`:

```bash
source ${CLAUDE_PLUGIN_ROOT}/scripts/predeploy-gate.sh
```

(Substitute the absolute path to the plugin if `CLAUDE_PLUGIN_ROOT` isn't set in your shell.)

Now in your terminal:

```bash
vercel deploy --prod
# 🚦  agentic-security pre-deploy gate
#     ✅  Safe to deploy. Proceeding...
# (deploy proceeds)

vercel deploy --prod
# 🚦  agentic-security pre-deploy gate
#     🛑  BLOCKED: 2 critical finding(s)
# (deploy is refused, exit 1)
```

Bypass once: `AS_GATE_OVERRIDE=1 vercel deploy --prod`.

## Standalone check

Outside any deploy command:

```bash
bash scripts/predeploy-gate.sh check
```

Returns exit 0 if safe, 1 if blocking. Useful in your own CI workflow.

## How to apply this command

Parse `${1}`:

- `install` (default): write a default `.agentic-security/predeploy-gate.json`, then print the one-line `source` snippet for the user's shell profile.
- `check`: run `bash scripts/predeploy-gate.sh check`.
- `status`: print the config and last-scan info.
- `off`: delete the config or set `"block_on": []`.

🛡  agentic-security · created by Clear Capabilities
