---
description: Post a daily security digest to Slack / Discord / a generic webhook. Tells you what's new since yesterday, what got resolved, and which KEV (known-exploited) packages are in your tree. Designed for indie builders who want async security awareness without opening a dashboard.
argument-hint: "[--setup | --slack <url> | --discord <url> | --webhook <url> | --crontab]"
---

# Daily security check-in

You don't open security dashboards. You DO open Slack and Discord. This command does a daily scan + delta and DMs you the result wherever you already are.

## What the digest looks like

```
🛡  myapp — daily security digest  (2026-05-14 09:00 UTC)

  Open:   2 critical · 5 high · 11 medium
  ⚠️  3 new finding(s) since last digest:
     • [CRITICAL] Hardcoded API key — src/lib/openai.ts:8
     • [HIGH] Missing rate limit — src/app/api/chat/route.ts:42
     • [HIGH] CORS wildcard with credentials — src/middleware.ts:14
  ✓ 2 finding(s) resolved 🎉
  🚨 KEV (known-exploited) packages in tree: 1

  Run /scan --all for full details, or /find-and-fix-everything to auto-remediate.
```

## Setup

```bash
# Interactive — prompts you for Slack/Discord webhooks
/daily-checkin --setup

# Or one-shot configure:
/daily-checkin --slack https://hooks.slack.com/services/...
/daily-checkin --discord https://discord.com/api/webhooks/...
/daily-checkin --webhook https://your-server/security-hook   # generic JSON POST
```

Webhooks are stored in `.agentic-security/daily-checkin.json` — gitignore it.

## Scheduling

```bash
# Get the suggested crontab line
/daily-checkin --crontab

# Or set up via GitHub Actions:
# .github/workflows/daily-security-checkin.yml
on:
  schedule:
    - cron: '0 9 * * *'
jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python3 scripts/daily-checkin.py --rescan
        env:
          DAILY_CHECKIN_SLACK: ${{ secrets.SLACK_WEBHOOK }}
```

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daily-checkin.py ${ARGS}
```

If no webhook is configured AND the user didn't pass `--setup`, gently nudge them:
*"You haven't set up a destination yet. Want to run `/daily-checkin --setup` to wire it to Slack or Discord?"*

## Delta tracking

State is kept in `.agentic-security/daily-checkin-last.json` — a fingerprint of the previous digest. This lets the command tell you what changed since yesterday, not just what exists today (which is the dashboard view). Vibe-coders care about deltas, not totals.

## Privacy

- The digest payload contains **no source code** — just finding IDs, vuln names, file paths, line numbers.
- Slack/Discord webhooks are end-to-end yours; nothing routes through Clear Capabilities or any third party.
- Generic webhook mode posts the full digest JSON to your URL — bring your own server if you don't want Slack/Discord at all.

🛡  agentic-security · created by Clear Capabilities
