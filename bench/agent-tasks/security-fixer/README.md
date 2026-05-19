# Agent-task corpus — security-fixer

Eval corpus for the `security-fixer` subagent. Each task exercises the
deterministic toolchain the agent depends on (`synthesize_fix` →
`verify_fix` → `apply_fix`) end-to-end against a real fixture.

This is intentionally NOT an LLM-in-the-loop benchmark — the LLM only chooses
WHICH finding to act on and confirms appropriateness. The bytes-on-disk path
is deterministic, and that's what this corpus measures.

## What it measures

For each task:

| Grader | Pass condition |
|--------|----------------|
| `fix_applied`     | `apply_fix` returned `applied: true` |
| `stableId_closed` | re-scan no longer surfaces the original `stableId` |
| `no_new_high`     | re-scan does not introduce any new `severity >= high` finding |
| `single_attempt`  | the fix landed on the first attempt (no retry budget consumed) |
| `verify_passed`   | `verify_fix` reported `ok: true` before `apply_fix` ran |

The runner reports per-task per-grader results and an aggregate `pass@1` rate.

## Task spec

Each `tasks/<id>.json`:

```json
{
  "id": "sqli-flask-concat",
  "description": "...",
  "fixture_path": "bench/cve-replay/capability/CVE-XYZ/pre",
  "target": {
    "vuln_match": "sql injection",
    "cwe": "CWE-89"
  },
  "graders": ["fix_applied", "stableId_closed", "no_new_high", "single_attempt", "verify_passed"]
}
```

The runner copies `fixture_path` to a fresh temp dir per trial (clean-slate
isolation, per the eval post: "each trial should be isolated by starting from
a clean environment"). After the run the temp dir is removed.

## Run

```bash
cd scanner
node ../bench/agent-tasks/security-fixer/runner.mjs
node ../bench/agent-tasks/security-fixer/runner.mjs --json
node ../bench/agent-tasks/security-fixer/runner.mjs --task sqli-flask-concat
```

## Adding a task

1. Pick or create a fixture pair under `scanner/test/fixtures/` or
   `bench/cve-replay/`. The fixture's `pre/` shape must produce a finding the
   scanner emits with `fix.replacement` populated — not every detector
   produces a synthesizable replacement.
2. Run the scanner once against the fixture and confirm the finding you want
   to target appears in `last-scan.json`. Note its `family` and `cwe`.
3. Write `tasks/<id>.json` with the `target.vuln_match` regex (case-insensitive)
   and the `cwe`.
4. Run the runner with `--task <id>` to verify each grader fires correctly.

## Why this is an agent eval, not a scanner test

The scanner test suite (`scanner/test/`) verifies the scanner's outputs.
This corpus verifies the **subagent's** harness: that when the agent picks a
finding and follows the deterministic toolchain (`synthesize_fix` →
`verify_fix` → `apply_fix`), the result actually closes the issue without
introducing a regression. Per Anthropic's evals post: *"there is a common
instinct to check that agents followed very specific steps… It's often
better to grade what the agent produced, not the path it took."* This corpus
grades the produced state.
