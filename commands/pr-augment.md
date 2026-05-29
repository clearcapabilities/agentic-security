---
description: Generate a security-review block for a PR description — diff vs base branch, ATT&CK tactics, reviewers, artifact links.
argument-hint: "[--base <ref>] [--persist-baseline] [--write] [--print]"
---

# /pr-augment

Generate a Markdown security-review block for the current PR's description.

## What it does

1. Reads the current `.agentic-security/last-scan.json`
2. Diffs against `.agentic-security/scan-baselines/<base>.json` if present
3. Produces a Markdown block with:
   - Findings delta (added / removed by severity)
   - 🛑 block-merge banner if new criticals
   - MITRE ATT&CK techniques surfaced by new findings
   - Suggested reviewer teams (security, privacy, platform, ml)
   - Top 5 added findings
   - Links to posture artifacts (threat-model, compliance evidence, PQC plan, etc.)

## Modes

- `--print` (default) — output the Markdown block to stdout
- `--write` — pipe the block into `gh pr edit --body-file -` for the current PR
- `--persist-baseline` — save the current scan as the baseline for `<base>` for future PRs

## Usage

```bash
# Print the block (default)
/pr-augment

# Use a non-main base
/pr-augment --base develop

# Save the current main scan as the baseline so future PRs can diff against it
/pr-augment --persist-baseline

# Apply the block to the current PR via gh
/pr-augment --write
```

## Implementation

This command calls `posture/pr-augment.js#augmentPrBody`. The base ref defaults to `main`.

The agent should:

1. Read `~/.agentic-security/last-scan.json` to confirm a scan exists.
2. Call the module entry:
   ```js
   const { augmentPrBody, persistBaseline } = await import('@clear-capabilities/agentic-security-scanner/posture/pr-augment.js');
   const { body } = augmentPrBody(scanRoot, { baselineRef: 'main' });
   ```
3. If `--write`: run `gh pr edit --body-file <(echo "$body")` against the current PR (or `gh pr create --body "$body"` if no PR exists yet).
4. If `--print`: write `body` to stdout.

If the user passes `--persist-baseline`, persist the current scan as the baseline:
```js
persistBaseline(scanRoot, baseRef, scan);
```
The user should run `--persist-baseline` once from a clean `main` to enable diff mode.
