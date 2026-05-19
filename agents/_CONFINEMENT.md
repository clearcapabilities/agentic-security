# Subagent path-confinement schema (premortem #17)

Subagents that hold `Edit` MUST follow the same write-confinement contract
the MCP server enforces (`scanner/src/mcp/tools.js`). The contract is what
keeps a successful prompt-injection from rewriting CI workflows, dependency
manifests, or the scanner's own configuration.

## The contract

Refuse to write to any path that:

1. Resolves outside the scan root (lexical `..` or symlink-traversal).
2. Is reserved as scanner / source-control / dependency / CI state:
   - `.git/`, `.github/`, `.gitlab/`, `.circleci/`, `.buildkite/`
   - `.agentic-security/`
   - `node_modules/`, `.terraform/`, `.aws/`, `k8s/`, `kubernetes/`
   - File basenames: `Dockerfile`, `Jenkinsfile`, `.gitlab-ci.yml`,
     `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
     `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`,
     `requirements.txt`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`,
     `composer.json`, `composer.lock`, `Gemfile`, `Gemfile.lock`, `pom.xml`,
     `build.gradle`, `build.gradle.kts`
   - Suffixes: `*.tf`, `*.tfvars`, `docker-compose.yml`, `docker-compose.yaml`
3. Is a backup, lock, or build-output file (`*.bak`, `*.lock`, `dist/`,
   `build/`, `target/`).

If the user explicitly asks for one of these in their prompt, the subagent
should refuse with a one-line explanation and a pointer to `/rotate-key-auto`
(for credential files), `/install-hooks` (for `.git/hooks/`), or
`/ci-gate` / `/ci-gate-multi` (for CI workflows).

## What is allowed

Edits under the scan root that are NOT on the reserved list. Apply the
finding's stored `fix.replacement` verbatim — do not paraphrase, do not
"improve while you're there." The verifier and history depend on the patch
being exactly what the scan produced.

## Verification

Before claiming a fix is applied, every Edit-capable subagent SHOULD:

1. Run `verify_fix` (via MCP) on the proposed patch in memory.
2. Refuse to commit the change if `verify_fix` reports the original
   `stableId` is still present OR if a new ≥medium finding was introduced.
3. Report the outcome (re-scan + lint verdict) back to the caller.

## Why this matters

Premortem #17: a successful prompt-injection attack on a subagent that holds
Edit but no confinement contract is equivalent to a successful attack on the
MCP `apply_fix` tool — but without any of the hardening the MCP path enforces
(HMAC on findings, reserved-paths refusal, audit log). The path the attacker
would use is whichever has the least friction; we close it here.
