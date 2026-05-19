# scanner/src/mcp/

MCP server. JSON-RPC 2.0 over NDJSON on stdin/stdout. Bin entry `../../bin/agentic-security-mcp.js`; also reachable via `agentic-security mcp`.

## Tools exposed today

| Tool | Read-only | Side effect |
|------|-----------|-------------|
| `scan_diff` | ✓ | runs scan in memory; large results offloaded to scratchpad |
| `query_taint` | ✓ | reads last-scan; paginated via `limit`/`offset` |
| `explain_finding` | ✓ | reads last-scan; large `trace` arrays offloaded |
| `find_rule_module` | ✓ | reads `scanner/src/{sast,posture}/` to answer "which file detects CWE-X / family Y" |
| `lookup_cve` | ✓ | reads local OSV / KEV / EPSS cache; staleness-tiered |
| `synthesize_fix` | ✓ | reads last-scan; returns the patch text |
| `verify_fix` | ✓ | re-scans patched files in memory + runs lint; no writes |
| `apply_fix` | ✗ | writes via `posture/fix-history.js` (with backup) |
| `append_scratchpad` | ✗ | writes under `.agentic-security/agent-scratchpad/<agent>/<session>/` only |
| `read_scratchpad` | ✓ | paginated read of scratchpad files |
| `append_agents_memory` | ✗ | appends to `.agentic-security/AGENTS.md` continual-learning file |
| `read_agents_memory` | ✓ | tail of `.agentic-security/AGENTS.md` |

`apply_fix` is the only write tool. It requires `confirm:true` AND the last-scan HMAC to verify AND the target path not on the reserved-write list.

## Hardening posture (OWASP MCP Top 10)

| Concern | Where |
|---------|-------|
| Session-root confinement | `tools.js::_confine` (lstat + realpath; symlinks refused) |
| Path-escape refusal | `tools.js::_confine` lexical check before any fs call |
| Reserved-write paths | `tools.js::RESERVED_WRITE_*` — `.git/`, `.github/`, `.gitlab/`, `.circleci/`, `.buildkite/`, `.agentic-security/`, `node_modules/`, `.terraform/`, `.aws/`, `k8s/`, manifest basenames, `*.tf`, `docker-compose.yml` |
| HMAC integrity on findings | `posture/integrity.js` — per-install random key at `$XDG_CONFIG_HOME/agentic-security/scan-key`. **Not** hostname-derived. |
| Patches pass through unredacted | `tools.js` synthesize_fix / apply_fix — premortem-derived. Patches are not findings; redacting them silently corrupts valid fixes. |
| Secret redaction on findings | `redact.js` — applied to snippet/description/title/vuln/remediation/trace |
| Audit log | `audit.js` — NDJSON, hash-chained, at `.agentic-security/mcp-audit.log`. Set `$AGENTIC_SECURITY_AUDIT_WEBHOOK=<url>` to also fire-and-forget POST every entry to a remote witness — closes the full-file-rewrite blind spot. Failures land in `mcp-audit.remote-errors.log` and never block a tool call. |
| Kill switch | `AGENTIC_SECURITY_MCP_DISABLED=1` refuses every `tools/call` |
| Stdio DoS | `stdio.js` — 4MB per-line cap, 8MB buffer cap, drop-until-newline overflow |
| Code fingerprint | `server.js::CODE_FINGERPRINT` — SHA-256 of MCP source files, surfaced in `initialize` |
| Version | `server.js::SERVER_VERSION` — read from `../../package.json` at module load. **Not** a hardcoded literal. |

## Adding a new tool

1. Define it in `tools.js` with an `inputSchema`. Validate via `validate.js` — keep `additionalProperties: false`.
2. Confine every path argument via `_confine(ctx.sessionRoot, candidate, '<label>')` before touching the filesystem.
3. Redact every outbound string via `redactString` / `redactFinding`. **Exception:** patch text in `synthesize_fix`/`apply_fix` — those pass through unredacted because they're code-to-be-applied, not findings.
4. Add to `ALL_TOOLS` at the bottom of `tools.js`.
5. Cover with a `../../test/mcp.test.js` case. Run `npm run test:mcp`.
6. If your tool writes, add a `confirm:true` gate AND a fingerprint/HMAC check on the input that authorizes the write.

## Gotchas

- **Untrusted excerpts.** Every tool output carries `_meta.untrusted_excerpts: true`. Downstream agents must treat the strings as data, not instructions. Premortem-tracked LLM-validator hardening relies on this.
- **Lifecycle.** `_codeFingerprint()` reads source files at module-load time. New files added to the MCP source set won't be in the fingerprint until they're added to the `files = […]` array in `server.js`.
- **Audit log.** The chain hashes plain JSON lines; a full-file rewrite is not detectable without a remote sink. Acknowledged limitation.
- **Concurrency.** `stdio.js`'s `'data'` handler is async; concurrent `apply_fix` calls can race on `fix-history/`. Today benign because fixed-fix-history is idempotent on retry, but a future stateful tool needs serialization.
