// Stdio transport for the MCP server — newline-delimited JSON in/out.
//
// MCP's stdio transport is NDJSON: one JSON-RPC message per line on stdin,
// one response per line on stdout. stderr is reserved for logging.
//
// Hardening:
//   - Per-message line cap (MAX_LINE_BYTES). A line over the cap is dropped
//     and the buffer state is reset so a long oversize payload can't peg
//     the parser via `buf += chunk` growth.
//   - Buffer hard cap (MAX_BUFFER_BYTES). Reached if input arrives with no
//     newlines (e.g., a peer streaming a 4GB stream of `a`). On overflow we
//     emit a parse-error response and reset.

import { createServer } from './server.js';

const MAX_LINE_BYTES = 4 * 1024 * 1024;        // 4 MB per JSON-RPC message
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;      // 8 MB sliding buffer

export function runStdio({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  sessionRoot = process.cwd(),
} = {}) {
  const server = createServer({ sessionRoot });
  let buf = '';
  let overflowSkip = false; // true while we are dropping bytes until the next newline

  stdin.setEncoding('utf8');

  stdin.on('data', async (chunk) => {
    if (overflowSkip) {
      const nl = chunk.indexOf('\n');
      if (nl === -1) return;
      // Resume after the next newline.
      chunk = chunk.slice(nl + 1);
      overflowSkip = false;
    }

    buf += chunk;

    // Hard buffer cap — only triggers if a peer is streaming without newlines.
    if (buf.length > MAX_BUFFER_BYTES) {
      stderr.write(`mcp: input buffer exceeded ${MAX_BUFFER_BYTES} bytes — dropping until next newline\n`);
      const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: input too large' } };
      stdout.write(JSON.stringify(errResponse) + '\n');
      buf = '';
      overflowSkip = true;
      return;
    }

    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      if (line.length > MAX_LINE_BYTES) {
        stderr.write(`mcp: dropped oversize line (${line.length} > ${MAX_LINE_BYTES} bytes)\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: line too large' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      let msg;
      try { msg = JSON.parse(line); }
      catch (e) {
        stderr.write(`mcp: failed to parse line as JSON: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      try {
        const response = await server.handleRequest(msg);
        if (response !== null) stdout.write(JSON.stringify(response) + '\n');
      } catch (e) {
        stderr.write(`mcp: handler threw: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: 'Internal error', data: e.message } };
        stdout.write(JSON.stringify(errResponse) + '\n');
      }
    }
  });

  stdin.on('end', () => { process.exit(0); });
}
