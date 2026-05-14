---
description: Audit every LLM API call in your codebase, auto-patch missing max_tokens caps, generate rate-limit middleware, and emit a daily $-spend tracker. Vibe-coder protection against the worst LLM-app failure mode — prompt injection on an uncapped endpoint that drains thousands of dollars in hours.
argument-hint: "[--audit | --apply | --generate-middleware | --generate-tracker --daily-cap 50]"
---

# LLM cost ceiling

You ship an AI app. You forget to set `max_tokens`. An attacker sends a prompt that says "respond with the entire Bible verbatim five hundred times." Your OpenAI bill hits $40,000 by morning.

This command makes that impossible.

## What it does

**Audit**: Walks your codebase, finds every `client.messages.create(...)`, `openai.chat.completions.create(...)` etc., and reports which calls have no `max_tokens` cap.

**Auto-patch**: With `--apply`, injects `max_tokens: 1024` into every uncapped call (configurable). The patch is reviewable via `git diff`.

**Rate-limit middleware**: With `--generate-middleware`, writes a drop-in rate-limiter for your framework (Next.js App Router / Express / Fastify / FastAPI). Default: 20 calls per IP per minute.

**Spend tracker**: With `--generate-tracker`, writes a per-day USD tracker module that throws once the daily cap is hit. Wrap your LLM calls with `trackAndGate({ dailyCapUsd: 50 })`.

## Usage

```bash
# Audit only
/llm-cost-ceiling

# Audit + auto-patch every missing max_tokens
/llm-cost-ceiling --apply

# Generate the rate-limit middleware for your framework
/llm-cost-ceiling --generate-middleware

# Generate spend tracker with a $50/day cap
/llm-cost-ceiling --generate-tracker --daily-cap-dollars 50

# Do everything
/llm-cost-ceiling --apply --generate-middleware --generate-tracker --daily-cap-dollars 50
```

## What gets detected

| SDK | Pattern |
|---|---|
| Anthropic (JS/TS) | `anthropic.messages.create(...)`, `client.messages.create(...)` |
| OpenAI v4 (JS/TS) | `openai.chat.completions.create(...)` |
| OpenAI legacy (JS/TS) | `openai.completions.create(...)` |
| Anthropic (Python) | `client.messages.create(...)`, `anthropic.messages.create(...)` |
| OpenAI (Python) | `client.chat.completions.create(...)` |

Recognised cap keys: `max_tokens`, `max_completion_tokens` (OpenAI o1/o3), `max_output_tokens` (Gemini).

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/llm-cost-ceiling.py ${ARGS}
```

Where `ARGS` is the user's flags. If the user didn't pass any flag, show the audit. Then offer:
*"You have N uncapped LLM calls. Want me to auto-patch them all with `max_tokens: 1024`? You can review the changes with `git diff` before committing."*

If they say yes, re-run with `--apply`. Then offer the middleware and tracker generators.

Exit code: `1` if any uncapped calls remain (suitable for CI gate).

🛡  agentic-security · created by Clear Capabilities
