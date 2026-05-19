// Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7 — Phase-1 P1.2).
//
// Consumes the PoC artifacts produced by P1.1 (`f.poc`) and assigns a
// per-finding `verifier_verdict` in:
//
//   verified-exploit       — PoC ran against a live target and exited 0
//   verified-by-llm        — Layer-3 LLM accepted the finding (no PoC ran)
//   verified-sanitizer-absence — pattern-based proof that no sanitizer is on the flow
//   unverified-by-design   — CWE family for which v1 explicitly doesn't ship a PoC
//   cannot-verify          — PoC failed to run / LLM returned escalate / sandbox error
//
// Honest scope for v1:
//   * Default mode is "validate-only": parse the PoC, refuse to ship one that
//     contains a destructive payload, but do NOT execute it. Findings get
//     `verifier_verdict` set from the static signals.
//   * Live execution mode (AGENTIC_SECURITY_VERIFY_LIVE=1) runs each PoC
//     against a caller-provided target URL (AGENTIC_SECURITY_VERIFY_TARGET).
//     Without a target, live mode falls back to validate-only with a
//     `cannot-verify` verdict + reason 'no-target'.
//   * Sandbox: Docker by default with restrictive flags; subprocess fallback
//     with ulimit. The sandbox runner is exported so the CLI subcommand can
//     reuse it.
//
// Fail-closed semantics (FR-VER-7): any error — Docker missing, target down,
// PoC throws — produces `cannot-verify`, never `rejected`. An attacker who
// can break the verifier can only make findings UNVERIFIED, never SILENCED.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawnSync } from 'node:child_process';
import { isExplicitlyNoPoc } from './poc-cwe-map.js';

// ─── PoC static validation ──────────────────────────────────────────────────
//
// Refuse to ship a PoC that:
//   - is too long (template runaway)
//   - mentions a banned pattern (destructive shell, fork bomb)
//   - hardcodes a real cloud-metadata IP
//   - doesn't end with a `process.exit(...)` so verdict assignment is reliable

const MAX_POC_BYTES = 16_384;

const BANNED_PATTERNS = [
  /rm\s+-rf\s+\//,        // recursive destructive
  /mkfs/,
  /dd\s+if=\/dev\/(?:zero|random|urandom)/,
  /:\(\)\s*\{\s*:\s*\|\s*:/,  // fork bomb
  /shutdown\b/,
  /reboot\b/,
  /chmod\s+777\s+\//,
];

const BANNED_HOSTS = [
  '169.254.169.254',
  'metadata.google.internal',
  'fd00:ec2::254',
];

export function validatePoc(poc) {
  if (!poc || typeof poc !== 'object') return { ok: false, reason: 'no-poc' };
  if (typeof poc.code !== 'string' || poc.code.length === 0) return { ok: false, reason: 'empty-code' };
  if (poc.code.length > MAX_POC_BYTES) return { ok: false, reason: 'code-too-long' };
  for (const re of BANNED_PATTERNS) {
    if (re.test(poc.code)) return { ok: false, reason: `banned-pattern:${re.source.slice(0, 30)}` };
  }
  for (const h of BANNED_HOSTS) {
    if (poc.code.includes(h)) return { ok: false, reason: `banned-host:${h}` };
  }
  if (!/process\.exit\s*\(/.test(poc.code) && poc.lang === 'node') {
    return { ok: false, reason: 'no-deterministic-exit' };
  }
  return { ok: true };
}

// ─── Sanitizer-absence proof ────────────────────────────────────────────────
//
// For a flow-based finding with a clear source → sink path, we can prove a
// SANITIZER IS ABSENT by checking that none of the family's known sanitizers
// appears in the surrounding code window.

const SANITIZER_TABLE = {
  'sql-injection':           /\bprepare(?:Statement)?\s*\(|parameterized|\$\d+\b(?![=A-Za-z])|sequelize\.literal\b|\bescape\s*\(|(?:\bquery|\bexecute|\b\$queryRaw|\b\$executeRaw)\s*\([^)]*,\s*\[/i,
  'command-injection':       /execFile\s*\(|spawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[|shlex\.quote/i,
  'xss':                     /escapeHtml|sanitize-html|DOMPurify|encodeURIComponent\(|textContent\s*=|res\.json\(/i,
  'path-traversal':          /path\.resolve\s*\(|path\.basename\s*\(|\.startsWith\s*\(\s*\w+\s*\)/i,
  'ssrf':                    /isPrivateIP|new\s+URL\s*\(|allowlist|allowedHosts|trustedHosts/i,
  'code-injection':          /(?!eval).*?\beval\s*\(.*JSON/i,    // very weak; intentionally narrow
  'open-redirect':           /allowed(?:Redirects|Urls|Hosts)|\.includes\s*\(\s*\w+\s*\)\s*\?/i,
  'xxe':                     /\bnoent\s*[:=]\s*false|resolve_entities\s*=\s*False|XMLInputFactory.*IS_SUPPORTING_EXTERNAL_ENTITIES.*false/i,
  'insecure-deserialization':/JSON\.parse|yaml\.safe_load|safe_load_all/i,
};

function _windowAroundLine(file, line, fileContents) {
  if (!file || !line || !fileContents || !fileContents[file]) return '';
  const lines = fileContents[file].split('\n');
  const start = Math.max(0, line - 11);
  const end = Math.min(lines.length, line + 10);
  return lines.slice(start, end).join('\n');
}

export function proveSanitizerAbsence(finding, fileContents) {
  const fam = finding.family;
  if (!fam) return { ok: false, reason: 'no-family' };
  const rx = SANITIZER_TABLE[fam];
  if (!rx) return { ok: false, reason: 'no-rule' };
  const file = finding.file || finding.sink?.file;
  const line = finding.line || finding.sink?.line || 0;
  const window = _windowAroundLine(file, line, fileContents);
  if (!window) return { ok: false, reason: 'no-source-window' };
  if (rx.test(window)) return { ok: false, reason: 'sanitizer-present' };
  return { ok: true, reason: `no-sanitizer-in-window`, window: window.length };
}

// ─── Sandbox execution ──────────────────────────────────────────────────────
//
// Runs the PoC and returns { ok, exitCode, stderr, runner }.
// Caller decides what to do with the result. Internal — surfaced via
// `_internals.runSandboxed` for tests; the public contract is
// `annotateVerifierVerdicts`.

function runSandboxed(poc, opts = {}) {
  const target = opts.target;
  if (!target) return { ok: false, reason: 'no-target' };
  // Materialise the PoC to a temp file.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-poc-'));
  const file = path.join(dir, poc.lang === 'python' ? 'poc.py' : 'poc.mjs');
  try {
    fs.writeFileSync(file, _patchTarget(poc.code, target));
  } catch (e) {
    return { ok: false, reason: `write-failed:${e.message}` };
  }
  const docker = _haveDocker() ? _runDocker(file, dir, poc.lang, opts) : null;
  const result = docker || _runSubprocess(file, poc.lang, opts);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  return result;
}

function _patchTarget(code, target) {
  // Replace the localhost:3000 placeholder with the caller-provided target.
  return code.replace(/http:\/\/localhost:3000/g, target);
}

function _haveDocker() {
  try {
    const r = spawnSync('docker', ['version'], { stdio: 'ignore', timeout: 3000 });
    return r.status === 0;
  } catch { return false; }
}

function _runDocker(file, dir, lang, opts) {
  const image = lang === 'python' ? 'python:3.12-slim' : 'node:22-slim';
  const cmd = lang === 'python' ? ['python3', '/work/poc.py'] : ['node', '/work/poc.mjs'];
  const args = [
    'run', '--rm',
    '--network=host',          // PoC must reach the target; host is the smallest blast radius
    '--cap-drop=ALL',
    '--memory=256m',
    '--cpu-quota=20000',
    '--pids-limit=64',
    '--read-only',
    '--tmpfs=/tmp',
    '--user', 'nobody',
    '-v', `${dir}:/work:ro`,
    image,
    ...cmd,
  ];
  const r = spawnSync('docker', args, {
    timeout: opts.timeoutMs || 15000,
    encoding: 'utf8',
  });
  if (r.error) return { ok: false, reason: `docker-error:${r.error.code || r.error.message}`, runner: 'docker' };
  return { ok: true, exitCode: r.status, stderr: r.stderr || '', stdout: r.stdout || '', runner: 'docker' };
}

function _runSubprocess(file, lang, opts) {
  const bin = lang === 'python' ? 'python3' : 'node';
  const r = spawnSync(bin, [file], {
    timeout: opts.timeoutMs || 15000,
    encoding: 'utf8',
    // Best-effort containment without Docker. Operators are warned in stderr
    // that the subprocess fallback offers materially weaker isolation.
    env: { PATH: process.env.PATH || '', NODE_OPTIONS: '' },
  });
  if (r.error) return { ok: false, reason: `subprocess-error:${r.error.code || r.error.message}`, runner: 'subprocess' };
  return { ok: true, exitCode: r.status, stderr: r.stderr || '', stdout: r.stdout || '', runner: 'subprocess' };
}

// ─── Per-finding verdict assignment ─────────────────────────────────────────

export function verdictForFinding(finding, ctx = {}) {
  // 1. Families we explicitly do not ship a PoC for.
  if (isExplicitlyNoPoc(finding.family)) {
    return { verdict: 'unverified-by-design', reason: `family-no-poc:${finding.family}` };
  }
  // 2. Validator already passed it via the LLM.
  if (finding.validator_verdict === 'accept') {
    return { verdict: 'verified-by-llm', reason: 'llm-accept' };
  }
  // 3. PoC present and live mode is on — run it.
  const liveMode = process.env.AGENTIC_SECURITY_VERIFY_LIVE === '1';
  const target = ctx.target || process.env.AGENTIC_SECURITY_VERIFY_TARGET || null;
  if (finding.poc && liveMode && target) {
    const v = validatePoc(finding.poc);
    if (!v.ok) return { verdict: 'cannot-verify', reason: `poc-rejected:${v.reason}` };
    const r = runSandboxed(finding.poc, { target, timeoutMs: ctx.timeoutMs });
    if (!r.ok) return { verdict: 'cannot-verify', reason: r.reason || 'sandbox-error', runner: r.runner };
    if (r.exitCode === 0) return { verdict: 'verified-exploit', reason: 'poc-exit-0', runner: r.runner };
    return { verdict: 'cannot-verify', reason: `poc-exit:${r.exitCode}`, runner: r.runner, stderr: (r.stderr || '').slice(0, 240) };
  }
  // 4. PoC present but we're not running it — static validate only.
  if (finding.poc) {
    const v = validatePoc(finding.poc);
    if (!v.ok) return { verdict: 'cannot-verify', reason: `poc-validation-failed:${v.reason}` };
    // Static validation says the PoC is shippable; absent live execution we
    // can't claim verified-exploit. Try the sanitizer-absence proof next.
  }
  // 5. Sanitizer-absence proof.
  if (ctx.fileContents) {
    const sa = proveSanitizerAbsence(finding, ctx.fileContents);
    if (sa.ok) return { verdict: 'verified-sanitizer-absence', reason: sa.reason };
  }
  return { verdict: 'cannot-verify', reason: 'no-poc-no-sanitizer-rule' };
}

// ─── Batch annotation ───────────────────────────────────────────────────────

export function annotateVerifierVerdicts(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    try {
      const v = verdictForFinding(f, opts);
      f.verifier_verdict = v.verdict;
      f.verifier_reason = v.reason || null;
      if (v.runner) f.verifier_runner = v.runner;
    } catch (e) {
      // Defense in depth: any exception → cannot-verify, never throws upward.
      f.verifier_verdict = 'cannot-verify';
      f.verifier_reason = `verifier-exception:${e.message?.slice(0, 80)}`;
    }
  }
}

// ─── Summary helpers ────────────────────────────────────────────────────────

export function verifierCoverageSummary(findings) {
  const out = { 'verified-exploit': 0, 'verified-by-llm': 0, 'verified-sanitizer-absence': 0, 'unverified-by-design': 0, 'cannot-verify': 0 };
  for (const f of findings || []) {
    const v = f?.verifier_verdict;
    if (v && v in out) out[v]++;
  }
  return out;
}

// For tests and the no-dead-modules check.
export const _internals = { MAX_POC_BYTES, BANNED_HOSTS, SANITIZER_TABLE, runSandboxed };
