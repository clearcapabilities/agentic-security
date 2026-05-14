---
description: First-time-user walkthrough. Picks ONE real finding from the user's project, explains it in plain English, walks the user through fixing it, and applies the fix together. Reduces "I just installed this and don't know what to do" paralysis.
argument-hint: ""
---

# Onboarding tutor

A non-technical builder just installed `agentic-security`. They've never run a scanner before. They open the README. They see 14 slash commands. They close the README.

This skill is the antidote. The goal is to take them from "what do I do?" to "I just fixed a real security bug in my app, and I understand what happened" — in under 10 minutes.

## Flow

### Step 0 — Quick orientation

Before doing anything else, run a scan if `.agentic-security/last-scan.json` doesn't exist:

```bash
if [ ! -f .agentic-security/last-scan.json ]; then
  # Use the bundled scanner
  node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --all --no-network
fi
```

Then start the conversation:

```
Hi 👋  Let's walk through what this tool can do — together, on real code from
your project. This will take about 5–10 minutes. I won't run any commands
without asking you first.

What I'm about to show you is *one* security finding in your code, explained
plainly. By the end you'll know:
  - what the bug is
  - what an attacker would do with it
  - how to fix it
  - how to verify the fix actually worked

Ready? (yes / skip / quit)
```

### Step 1 — Pick the right finding

Read `last-scan.json`. Pick a finding that's **good for teaching**, in this priority order:

1. A `high` or `critical` finding with a clear, named CWE (CWE-89, CWE-78, CWE-22, CWE-79, CWE-639, CWE-918, CWE-798) — these have great stories and easy fixes.
2. If nothing critical/high, the most severe finding available.
3. If everything's clean (rare!), invert the experience: congratulate them, then offer to walk through a recent scan-history finding instead, or show them what a finding *would* look like with a synthetic example.

Skip these as teaching candidates:
- TOCTOU / race conditions (too abstract for a beginner)
- License/policy findings (not actionable as a "fix me" demo)
- Indeterminate / probable-FP findings (the demo should land cleanly)

### Step 2 — Show, don't tell (the visceral moment)

Read 30 lines of context around the finding's `file:line`. Then say something like:

```
Here's the file we're going to look at: src/api/users/[id]/route.ts

  35 │ export async function GET(req: Request, { params }) {
  36 │   const { id } = params;
  37 │
  38 │   // ← this is line 42, where the bug lives
  42 │   const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  43 │
  44 │   return Response.json(result.rows);
  45 │ }

Look at line 42. The id from the URL gets plugged straight into a SQL query
as text. That means if someone visits:

  /api/users/1' OR '1'='1

...then the SQL the database actually runs becomes:

  SELECT * FROM users WHERE id = 1' OR '1'='1

The trailing OR is always true, so the database returns EVERY user, not just
user 1. This is called SQL injection.

Want me to keep going? (yes / pause)
```

### Step 3 — Make it visceral, briefly

```
Just so you feel it: this isn't theoretical. Examples from real life:

  - 2017: Equifax — SQL injection → 147M records → $1.4B in costs
  - 2023: MOVEit Transfer — SQLi in a file-transfer tool → 95M records →
          400+ organizations affected
  - Last week: probably someone on Twitter

A bot scanning the internet for `OR '1'='1` patterns would find this in
about 30 seconds.
```

### Step 4 — The fix, with their hands on the wheel

```
The fix is one line. Instead of putting user input INTO the SQL string, we
pass it AS A SEPARATE ARGUMENT — the database driver then knows it's data
and never treats it as SQL syntax.

Here's the change:

  - const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  + const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);

Want me to apply this change to your file? (yes / let me do it / explain more)
```

If they say yes: use Edit to apply the fix. Don't apply it without explicit consent — this is a teaching moment.

### Step 5 — Verify the fix actually worked

After applying:

```
Now let's prove the fix actually stopped the bug. I'll run the scanner
again on just this file.
```

Re-scan the affected file. Compare. If the finding is gone:

```
✅ The scanner no longer reports this as a SQL injection. You just fixed
your first real security bug.
```

If the finding is still there:

```
Hmm, the scanner is still reporting it. Let me look again...
[debug the actual issue or escalate to a more thorough fix]
```

### Step 6 — What you can do next

```
That's the core loop. Here's what's available when you're ready:

  /scan                  Run the full scanner across your whole project
  /find-and-fix-everything   Scan + auto-fix everything at every severity
  /rotate-key-auto       If you ever leak an API key, rotate it end-to-end
  /llm-cost-ceiling      Caps LLM costs (do this BEFORE you ship an AI feature)
  /destructive-guard     Blocks dangerous shell commands (rm -rf, DROP TABLE, ...)
  /daily-checkin         Daily security digest to Slack/Discord
  /disaster-playbook     Generates your incident-response runbook
  /story-explain         Get this style of explanation for any finding
  /risk-in-dollars       See your findings as $ exposure instead of CVSS

You don't need to do them all. The ones I'd start with:

  1. /ai-bodyguard block        ← prevent the AI from writing insecure code
  2. /destructive-guard         ← prevent destructive shell commands
  3. /disaster-playbook         ← have an IR plan ready BEFORE you need it

Want me to set those three up now? (yes / not yet)
```

## Rules for the tutor

- **One finding only.** Don't try to teach everything at once. Pick ONE bug, walk through it deeply.
- **Ask before acting.** Every step that touches code or runs a command needs a yes.
- **Match the user's pace.** If they say "skip the story" or "just fix it", respect that. If they ask "why", explain more.
- **Don't shame the user.** The bug isn't their fault — most bugs come from AI-generated code, framework defaults, or copy-paste. Stay matter-of-fact.
- **Verify the fix.** The most important step is showing the scanner agrees the bug is gone. That's what makes the tutorial feel real.
- **End with concrete next steps,** not a wall of commands.

## When to invoke this skill

- The user just installed the plugin (first session).
- The user says something like "what do I do?", "where do I start?", "I don't know how to use this".
- The user asks a fundamental question about how the plugin works.

🛡  agentic-security · created by Clear Capabilities
