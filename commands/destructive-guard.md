---
description: Intercept destructive Bash commands before they run. Catches rm -rf, DROP TABLE, supabase db reset, git push --force to main, curl|bash, chmod 777, aws s3 rm --recursive, docker system prune -a, and 10+ other foot-guns vibe-coders most often regret.
argument-hint: "[on | off | warn | block | status]"
---

# Destructive command guard

The guard is a `PreToolUse` hook on `Bash` that watches the commands the agent is about to run. Default mode is **block** — for any `critical` pattern, the command is refused with a plain-English explanation of why and what to do instead. High-severity patterns get a warning but proceed.

## Modes

| Mode | Critical patterns | High patterns |
|---|---|---|
| `block` (default) | refused (exit 2) | warning printed, proceeds |
| `warn` | warning printed, proceeds | warning printed, proceeds |
| `off` | hook does nothing | hook does nothing |

## What it catches

| Pattern | Severity | Example |
|---|---|---|
| `rm -rf` on `/`, `~`, `..`, `/tmp`, `/var` | critical | `rm -rf /` |
| `rm -rf` with no target | critical | `rm -rf` |
| `DROP TABLE` / `DROP DATABASE` / `TRUNCATE` | critical | `psql -c "DROP TABLE users"` |
| `supabase db reset` | critical | wipes ALL data including production if linked |
| `git push --force` to main/master/prod | critical | overwrites canonical history |
| `git push --force` to any branch | critical | risks teammate work |
| `git reset --hard` | high | discards local AND popped-stash changes |
| `git clean -fdx` | high | also nukes .env and cached builds |
| `aws s3 rm --recursive` | critical | irreversible without versioning |
| `vercel --prod` direct | high | skips preview review |
| `curl ... \| bash` | high | supply-chain attack vector |
| `chmod 777` | high | world-writable = anyone modifies it |
| `docker system prune -a` | high | nukes more than you think |

## Usage

```
/destructive-guard block    # default — block criticals, warn highs
/destructive-guard warn     # warn but never block
/destructive-guard off      # disable entirely
/destructive-guard status   # show config + recent interceptions
```

Writes `.agentic-security/destructive-guard.json`:

```json
{
  "mode": "block",
  "extraPatterns": [
    { "name": "internal: don't touch the seed DB", "re": "seed\\.db", "severity": "high",
      "why": "team agreement", "instead": "use the dev DB instead" }
  ]
}
```

## Add your own patterns

Append to `extraPatterns` in the config — each entry takes `{name, re, severity, why, instead}`. Useful for project-specific lockdowns: paths only certain people should touch, deploy targets that need pre-flight, etc.

## How to apply this command

1. Parse `${1}` for mode. Treat `on` as `block` (the default).
2. If `status`: print the config and tail the recent hook activity if logged.
3. Otherwise write the config:

```bash
mkdir -p .agentic-security
cat > .agentic-security/destructive-guard.json <<EOF
{
  "mode": "${MODE}",
  "extraPatterns": []
}
EOF
```

4. Confirm activation with a one-line summary:

```
✓ Destructive-command guard set to ${MODE}.
  Hook: hooks/pre-bash-guard.js (auto-registered via hooks.json)
  Add custom patterns: edit .agentic-security/destructive-guard.json → extraPatterns[]
```

🛡  agentic-security · created by Clear Capabilities
