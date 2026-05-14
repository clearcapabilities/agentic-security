---
description: Real-time AI-coding bodyguard. Intercepts insecure code AS THE AI WRITES IT — before it hits disk — with high-precision rules for the bugs vibe-coders most often ship by accident (SQLi via concat, NEXT_PUBLIC_ secrets, dangerouslySetInnerHTML, JWT without verify, Supabase service-role on the client, LLM call with no max_tokens, etc.).
argument-hint: "[on | off | warn | block | status]"
---

# AI bodyguard

The bodyguard is a `PreToolUse` hook that scans the content Claude (or Cursor / Bolt / Lovable / any agent) is about to write into a file. It runs in-process, completes in ~10ms, and either lets the edit through or **blocks it** with a plain-English explanation of what would have gone wrong.

This is distinct from the post-edit scanner: the bodyguard is the just-in-time gate for the obvious foot-guns. The full scanner still runs after the edit lands.

## Modes

| Mode | Behavior |
|---|---|
| `warn` (default) | Print a warning to stderr; the edit proceeds. Good for first-time installs. |
| `block` | Block edits that match a CRITICAL rule. The agent gets a denial message and must fix or try again. |
| `off` | Hook does nothing. |

## Usage

```
/ai-bodyguard warn      # default — prints warnings, doesn't block
/ai-bodyguard block     # strict mode — blocks critical edits
/ai-bodyguard off       # disable
/ai-bodyguard status    # show current mode + recent interceptions
```

Behind the scenes this writes `.agentic-security/bodyguard.json`:

```json
{
  "mode": "block",
  "skipPaths": ["test/", "tests/", "fixtures/", "node_modules/"]
}
```

## What it catches (high-precision rules)

These rules are intentionally conservative — only the patterns where the FP rate is near-zero get triggered:

| Pattern | Severity | Why it matters to vibe-coders |
|---|---|---|
| SQL string concatenation into `db.query(...)` | critical | The AI keeps writing `` `SELECT ... WHERE id = ${id}` `` — direct SQLi |
| `exec()` / `os.system()` with template strings | critical | One bad prompt away from RCE |
| `NEXT_PUBLIC_*SECRET*` / `NEXT_PUBLIC_*API_KEY*` | critical | Secret leaks to the browser — the #1 vibe-coder mistake |
| Hardcoded `sk-...`, `ghp_...`, `xoxb-...`, `AKIA...`, `pk_live_*` | critical | Live API keys committed — costs you money fast |
| `dangerouslySetInnerHTML` without sanitize | high | XSS at scale |
| `eval()` / `new Function()` on user input | critical | RCE in the interpreter |
| `jwt.decode()` (instead of `jwt.verify()`) | high | Auth bypass — anyone can forge a token |
| Supabase `service_role` key in client-side code | critical | Bypasses every RLS rule you wrote |
| LLM `messages.create` without `max_tokens` | high | One prompt injection = $50K bill |
| CORS `*` + `Allow-Credentials: true` | critical | Cross-origin credential theft |

The full scanner catches everything else (post-edit). The bodyguard is the small set of *don't even think about it* checks.

## How to apply this command

1. Parse `${1}` for the desired mode (`on` is treated as `warn`).
2. If `status`: print the contents of `.agentic-security/bodyguard.json` and the last 10 lines of `.agentic-security/bodyguard.log` (if it exists).
3. Otherwise, write the config:

```bash
mkdir -p .agentic-security
cat > .agentic-security/bodyguard.json <<EOF
{
  "mode": "${MODE}",
  "skipPaths": ["test/", "tests/", "__tests__/", "fixtures/", "node_modules/"]
}
EOF
```

4. Confirm activation:

```
✓ AI bodyguard set to ${MODE}.
  Hook installed at:  hooks/pre-edit-bodyguard.js  (auto-registered via hooks.json)
  Config:             .agentic-security/bodyguard.json
  Override per-file:  add // bodyguard-ignore on the line above any pattern you intend to keep
```

5. If switching to `block` mode for the first time, gently warn:
   *"In block mode, any edit Claude tries to make that matches a critical pattern will be refused. You'll see the exact reason and can intervene. To go back, run `/ai-bodyguard warn`."*

🛡  agentic-security · created by Clear Capabilities
