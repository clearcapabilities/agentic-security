// C# structural detectors — PRD Tier 1.
//
// The main csharp.js is flow/taint-based and misses two corpus shapes:
//   - a hardcoded secret in a const/static field, SPLIT across concatenated
//     literals ("sk_" + "live_…") specifically to evade secret regexes;
//   - SSRF via WebClient/HttpClient on a non-validated URL.
// Both are regex/structural and complement the flow engine.

import { blankComments } from './_comment-strip.js';

const SECRET_PREFIX = /\b(?:sk_|sk-|AKIA|ghp_|gho_|xox[abps]-|AIza|eyJ|-----BEGIN|glpat-)/;
// A field whose name signals a credential, assigned a string (or concat of
// string literals — the splitting trick).
const SECRET_FIELD = /\b\w*(?:apikey|api_key|secret|token|password|passwd|pwd|credential|privatekey|connectionstring|accesskey)\w*\s*=\s*((?:"[^"]*"\s*\+\s*)*"[^"]*")/ig;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
// Join the contents of a concatenation of string literals.
function joinLiterals(expr) {
  const parts = expr.match(/"([^"]*)"/g) || [];
  return parts.map(p => p.slice(1, -1)).join('');
}

export function scanCsharpStructural(fp, raw) {
  if (!/\.cs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // Hardcoded secret in a credential-named field. The joined literal value must
  // look like a real secret (length or known prefix) so header-name constants
  // (ApiKeyHeader = "X-Api-Key") are not flagged.
  let m;
  const sre = new RegExp(SECRET_FIELD.source, SECRET_FIELD.flags);
  while ((m = sre.exec(code))) {
    const value = joinLiterals(m[1]);
    if (value.length < 16 && !SECRET_PREFIX.test(value)) continue;
    const line = lineOf(code, m.index);
    push({
      id: `csharp-hardcoded-secret:${fp}:${line}`, file: fp, line,
      vuln: 'Hardcoded credential in a const/static field (C#)',
      severity: 'high', cwe: 'CWE-798', family: 'secret', parser: 'CSHARP', confidence: 0.7,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Load the secret from the environment / a secrets manager (Environment.GetEnvironmentVariable, Azure Key Vault). Concatenating the literal to split it does not help — rotate the exposed value.',
    });
  }

  // SSRF: WebClient/HttpClient fetch from a non-literal URL, unless a host
  // allow/deny guard is present.
  const SSRF_SINK = /\.(?:DownloadString|DownloadData|OpenRead|GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync)\s*\(\s*[A-Za-z_]\w*\s*\)/;
  const SSRF_GUARD = /169\.254\.169\.254|\.Host\b|allow(?:ed)?Hosts?|IsLoopback|deny(?:list)?|block(?:list|ed)/i;
  if (SSRF_SINK.test(code) && !SSRF_GUARD.test(code)) {
    const line = lineOf(code, code.search(SSRF_SINK));
    push({
      id: `csharp-ssrf:${fp}:${line}`, file: fp, line,
      vuln: 'SSRF — HTTP client fetch from a non-validated URL (C#)',
      severity: 'high', cwe: 'CWE-918', family: 'ssrf', parser: 'CSHARP', confidence: 0.55,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Validate the URL host against an allow-list and reject RFC1918 / link-local / metadata (169.254.169.254) addresses before fetching.',
    });
  }

  return findings;
}
