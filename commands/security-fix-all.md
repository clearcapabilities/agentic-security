---
description: Walk through every finding at or above a severity threshold and fix them one at a time, with a plain-English confirmation per fix. Pass --auto for the silent batch flow.
argument-hint: "[--severity critical|high|medium] [--auto]"
---

Read `.agentic-security/last-scan.json` and apply remediation fixes.

## Default flow — interactive, plain-English (use this for non-engineers)

The default is **confirmation mode**: for each finding at or above the chosen severity threshold (default `critical`), do this in order:

1. Print a one-paragraph plain-English summary of the finding. Use `data/cwe-explainer.json` from the plugin to translate the CWE into a friendly description (Risk + How an attacker exploits it + How the fix works). If the CWE is missing from that table, fall back to the finding's own `fix` field.
2. Print where the change will land: `src/file.js:42` and a one-line preview of what the fix template will modify.
3. Pause and ask the user: `Fix this? [y]es / [s]kip / [d]iff first / [q]uit`.
4. On `y`: dispatch the `security-fixer` subagent. It reads the affected file, applies the fix template adapted to the surrounding code, and runs the project test command (if one is configured).
5. On `d`: show the proposed diff first, then ask again.
6. On `s`: skip and move to the next finding.
7. On `q`: stop the loop and print a summary of fixes applied so far.

Always print remaining count: `Fix 3 of 21 — SQL Injection in src/api/users.js:42. Fix this? [y/s/d/q]`.

After each accepted fix:
- Re-scan the file (`scanner --format json --since HEAD~0`) to verify the finding no longer reproduces and to detect any new findings the patch introduced.
- If tests fail, **do not auto-revert**. Stop the loop and report which fix broke which test. The user decides whether to revert manually (`git checkout <file>`) or keep the fix and update the test.

Critical first, then High (if requested), then Medium (if requested). Within a severity tier, order by `toxicityScore` descending.

## --auto flag — silent batch (use this for engineers / CI)

If the user passes `--auto`, skip the confirmation prompts entirely:
- Apply every fix in sequence (still in toxicity order).
- Stop on the first test failure or scan regression.
- Print a one-line summary at the end: `Applied N fixes, M skipped (tests failed), K regressions introduced.`

## --severity argument

| Value | Behaviour |
|---|---|
| `critical` (default) | Only critical findings |
| `high` | Critical + high |
| `medium` | Critical + high + medium |

## Agent notes

- Use the `security-fixer` subagent for every file edit.
- Never run with `--auto` on a dirty git tree without warning the user first.
- For confirmation prompts, render the explainer card *before* the question so the user can read it before deciding.
