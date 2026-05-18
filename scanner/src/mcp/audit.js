// Append-only audit log of MCP tool calls — OWASP MCP08.
//
// Format: one JSON object per line (NDJSON) at
//   <sessionRoot>/.agentic-security/mcp-audit.log
//
// Each entry carries `prev` — the SHA-256 of the previous entry's serialized
// form. The first entry's prev is "GENESIS". Tampering with any line breaks
// the chain from that point forward; a reader can detect partial truncation
// or in-place edits. (Cannot prevent total deletion of the file — for that
// you need write-once storage or a remote sink, out of scope for v1.)
//
// Argument blobs are redacted (OWASP MCP01/MCP10) so credentials passed in
// arguments cannot leak via the audit trail.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { redactArgsBlob } from './redact.js';

const MAX_ARG_BYTES = 1024;
const GENESIS = 'GENESIS';

function _summarize(args) {
  let s;
  try { s = JSON.stringify(args); } catch { s = '<unserializable>'; }
  s = redactArgsBlob(s);
  if (s.length > MAX_ARG_BYTES) s = s.slice(0, MAX_ARG_BYTES) + `…(+${s.length - MAX_ARG_BYTES})`;
  return s;
}

function _sha(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function _readLastEntryHash(logFile) {
  if (!fs.existsSync(logFile)) return GENESIS;
  try {
    const all = fs.readFileSync(logFile, 'utf8');
    const lines = all.split('\n').filter(Boolean);
    if (!lines.length) return GENESIS;
    return _sha(lines[lines.length - 1]);
  } catch { return GENESIS; }
}

export function auditCall({ sessionRoot, tool, args, outcome, reason }) {
  if (!sessionRoot) return;
  try {
    const dir = path.join(sessionRoot, '.agentic-security');
    fs.mkdirSync(dir, { recursive: true });
    const logFile = path.join(dir, 'mcp-audit.log');
    const entry = {
      ts: new Date().toISOString(),
      tool,
      outcome,
      ...(reason ? { reason } : {}),
      args: _summarize(args),
      prev: _readLastEntryHash(logFile),
    };
    fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
  } catch { /* audit failure must never break a tool call */ }
}

// Verify the chain from start to end. Returns
//   { ok: true, entries: N } if intact
//   { ok: false, brokenAt: <line-index>, expected, got } if any link breaks
// Reader/operator-facing tool.
export function verifyAuditLog(logFile) {
  if (!fs.existsSync(logFile)) return { ok: true, entries: 0 };
  const text = fs.readFileSync(logFile, 'utf8');
  const lines = text.split('\n').filter(Boolean);
  let expectedPrev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let entry;
    try { entry = JSON.parse(lines[i]); }
    catch { return { ok: false, brokenAt: i, reason: 'not JSON' }; }
    if (entry.prev !== expectedPrev) {
      return { ok: false, brokenAt: i, expected: expectedPrev, got: entry.prev };
    }
    expectedPrev = _sha(lines[i]);
  }
  return { ok: true, entries: lines.length };
}
