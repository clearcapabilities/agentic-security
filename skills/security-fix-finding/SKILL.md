---
name: agentic-security:security-fix-finding
description: Apply a remediation patch via the deterministic MCP toolchain. Activate when user asks to fix a scanner finding.
---

# Skill — fix a specific finding

Activates when the user is pointing at a specific finding from a prior
scan and wants to remediate it. The deterministic toolchain
(`synthesize_fix → verify_fix → apply_fix`) is the only correct path —
do NOT use `Edit` directly.

## When to fire

- User says "fix this one" / "how do I close X" / "patch the SQL injection at api/users.ts:42".
- User pastes a finding id (`struct:src/api.js:42:SQL_Injection`)
  or a stableId (`abc12345`) and asks for action.
- A prior turn produced a finding and the user said "ok do it".
- Conversation is in the middle of a triage flow.

## What to do

1. **Confirm the finding still exists.** Read
   `.agentic-security/last-scan.json` and look up the finding by id /
   stableId / file+line. If it's gone, tell the user and stop — don't
   patch a finding that's already been resolved.

2. **Decide appropriateness.** Read the file around `finding.line ± 30`
   via the `Read` tool. Is the canonical fix actually right here? If
   the surrounding code already validates upstream, or there's a custom
   sanitizer, or the file is a test fixture — STOP and report
   `refused: <reason>`. Don't proceed.

3. **Route via MCP, not Edit.** The deterministic path is:

   ```
   MCP synthesize_fix → MCP verify_fix → MCP apply_fix
   ```

   - `synthesize_fix({ finding_id })` returns the stored replacement
     text. You do NOT modify it. You do NOT retype it.
   - `verify_fix({ stable_id, files: {…} })` re-scans the patched file
     in memory and runs the project linter. Read the structured
     `introduced[]` array on failure (template-incomplete vs codebase-
     prior vs lint-failed — see `agents/security-fixer.md` for the
     decision tree).
   - `apply_fix({ finding_id, confirm: true })` writes via
     `fix-history.js` with HMAC verification + reserved-path refusal +
     attempt-budget enforcement.

4. **Batch mode.** If the user wants to fix more than one finding, hand
   off to the `security-fixer` subagent with a list (≤ 10 findings per
   invocation per `_CONFINEMENT.md`). The subagent writes a PLAN.md
   to the scratchpad.

5. **Run the project tests after apply.** If the project has
   `npm test`, `pytest`, `cargo test`, or similar — invoke it via
   Bash. Surface pass/fail in the final report.

## Don't

- Don't use `Edit` to apply security patches. The deterministic
  toolchain is the only path with HMAC + audit + budget + backup.
- Don't paraphrase the synthesized replacement. The bytes go through.
- Don't claim a fix is applied without a passing `verify_fix`.
- Don't grind through > 10 findings in one session — split into
  batches, write progress to AGENTS.md.

## Canonical commands

- `/fix --one <id>` — patch a single finding (interactive)
- `/fix --all --critical` — batch by severity
- `/fix --pr` — bundle into a PR branch
