#!/usr/bin/env node
// agentic-security MCP server — stdio entry point.
//
// Speaks JSON-RPC 2.0 over NDJSON on stdin/stdout. stderr is for logging.
//
// Usage:
//   node bin/agentic-security-mcp.js [--root <path>]
//
// Session root resolution (highest precedence first):
//   1. --root <path> CLI arg
//   2. AGENTIC_SECURITY_MCP_ROOT env var
//   3. process.cwd()
//
// The session root confines every tool: paths in tool arguments must resolve
// inside it, and apply_fix refuses any finding whose file field escapes it.

import * as path from 'node:path';
import { runStdio } from '../src/mcp/stdio.js';

function _parseRoot() {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root' && argv[i + 1]) return argv[i + 1];
    if (argv[i].startsWith('--root=')) return argv[i].slice('--root='.length);
  }
  return process.env.AGENTIC_SECURITY_MCP_ROOT || process.cwd();
}

// Operator kill-switch (OWASP MCP09 Shadow MCP Servers): bin exits
// immediately if disabled. Tool calls would also be refused server-side,
// but exiting early prevents the process from staying resident as an
// invisible attack surface on machines where the env var is set.
if (process.env.AGENTIC_SECURITY_MCP_DISABLED === '1') {
  process.stderr.write('mcp: disabled via AGENTIC_SECURITY_MCP_DISABLED=1 — exiting.\n');
  process.exit(0);
}

const sessionRoot = path.resolve(_parseRoot());
process.stderr.write(`mcp: session root = ${sessionRoot}\n`);
runStdio({ sessionRoot });
