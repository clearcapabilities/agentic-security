// HTTP Response Splitting / CRLF Injection (CWE-113).
//
// Pattern: a header value or `Location:` body is set from user input
// without stripping CR/LF. The attacker injects `\r\n\r\n<html>…` and
// splits the response, turning a single response into two — the second
// one fully attacker-controlled. Same root mechanism as open-redirect
// when the location is concatenated, but the consequence is broader
// (cache poisoning, XSS via injected body, session fixation).
//
// We catch:
//   - JS/Node:      res.setHeader('X-…', userValue)
//                   res.set('X-…', userValue)
//                   ctx.response.set('X-…', userValue)
//   - Java:         response.setHeader(…, name)
//                   response.addHeader(…, name)
//   - Python:       response['X-…'] = userValue       (Django)
//                   response.headers['X-…'] = userValue (Flask)
//   - PHP:          header("X-…: " . $_GET[...])  (also caught by open-redirect
//                   when Location:; this rule catches non-Location headers)
//
// Suppression: if the user value passes through a CRLF strip / regex
// filter / a known sanitizer (`escape`, `URLEncoder.encode`, `quote_plus`)
// in the preceding 30 lines, no finding.

import { blankComments } from './_comment-strip.js';

// Each pattern captures the header VALUE expression in its LAST group (the
// code reads the last defined group, so header-name groups can come first).
const PATTERNS = [
  // res.setHeader('name', val) | res.set('name', val) | ctx.response.set(…)
  ['js', /\b(?:res|reply|response|ctx\.response)\s*\.\s*(?:setHeader|set|append)\s*\(\s*[`"'][^`"']+[`"']\s*,\s*([^)]+?)\s*\)/g, 'res.setHeader'],
  // response.setHeader / response.addHeader  (Java Servlet API). Accept any
  // identifier as the receiver — `resp`, `response`, `httpResponse`, etc.
  ['java', /\b(?:[A-Za-z_][\w]*)\s*\.\s*(?:setHeader|addHeader|addIntHeader|setDateHeader)\s*\(\s*"[^"]+"\s*,\s*([^)]+?)\s*\)/g, 'setHeader'],
  // Django/Flask response.headers['X-…'] = userValue
  ['py', /\b(?:response|resp|r)\s*(?:\.\s*headers)?\s*\[\s*['"][^'"]+['"]\s*\]\s*=\s*([^\n;]+)/g, 'response.headers[…] = …'],
  // PHP header("X-Foo: " . $_GET[…])  (Location: variants handled by open-redirect)
  ['php', /\bheader\s*\(\s*['"](?!Location)([^'"]+):\s*['"]\s*\.\s*(\$\w[\w\[\]'"]*)/g, 'PHP header()'],
  // Go net/http: w.Header().Set/Add("X-…", value) | w.Header()["X-…"] = …
  ['go', /\.\s*Header\s*\(\s*\)\s*\.\s*(?:Set|Add)\s*\(\s*"[^"]+"\s*,\s*([^)]+?)\s*\)/g, 'Header().Set'],
  // Ruby Rack/Rails: response.headers["X-…"] = … | headers["X-…"] = … | response["X-…"] = …
  ['rb', /\b(?:response\s*(?:\.\s*headers)?|headers)\s*\[\s*['"][^'"]+['"]\s*\]\s*=\s*([^\n;]+)/g, 'response headers[…] = …'],
  // C#: Response.Headers.Add/Append("X-…", value) | Response.AddHeader(…) | Response.AppendHeader(…)
  ['cs', /\bResponse\s*\.\s*(?:Headers\s*\.\s*(?:Add|Append)|AddHeader|AppendHeader)\s*\(\s*"[^"]+"\s*,\s*([^)]+?)\s*\)/g, 'Response.Headers.Add'],
  // Kotlin: resp.setHeader("X-…", value) | resp.addHeader(…) — JVM servlet API
  ['kt', /\b(?:[A-Za-z_][\w]*)\s*\.\s*(?:setHeader|addHeader)\s*\(\s*"[^"]+"\s*,\s*([^)]+?)\s*\)/g, 'setHeader'],
];

const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|params\s*\[|query\.|body\.|ctx\.query|ctx\.request|reply\.query|c\.Query|r\.URL\.Query|_GET|_POST|_REQUEST|getParameter|getHeader)\b|\b(?:params|query|cookies|session)\s*\[/;

const SANITIZER_PATTERNS = [
  /\.replace\s*\(\s*\/\\r\?\\?n/i,                // .replace(/\r?\n/, '')
  /\.replace\s*\(\s*\/[\[]\\r\\n[\]]/i,           // .replace(/[\r\n]/, '')
  /\.replace\s*\(\s*['"]\\r['"]/,                 // .replace("\r", "") (Python/JS chain)
  /\.replace\s*\(\s*['"]\\n['"]/,                 // .replace("\n", "")
  /\.replaceAll\s*\(\s*['"]\\r?\\?n?['"]/,
  /\bgsub\s*\(\s*\/[\[]?\\r/i,                    // Ruby .gsub(/[\r\n]/, '') or /\r\n/
  /\bgsub\s*\(\s*\/[\[]\\r\\n[\]]/i,
  /\bdelete\s*\(\s*['"]\\r\\n['"]\s*\)/,          // Ruby .delete("\r\n")
  /\bstrings\.NewReplacer\s*\([^)]*\\r/,          // Go strings.NewReplacer("\r","","\n","")
  /\bstrings\.ReplaceAll\s*\([^,]+,\s*['"]\\[rn]['"]/,
  /\bstr_replace\s*\(\s*\[[^\]]*\\[rn]/,          // PHP str_replace(["\r","\n"], …)
  /\bstripNewlines\b/i,
  /\bsanitizeHeader\b/i,
  /\bescapeCRLF\b/i,
  /\bURLEncoder\s*\.\s*encode\b/,
  /\bquote_plus\s*\(/,
  /\bencodeURIComponent\s*\(/,
  /\bquote\s*\(/,
  // Explicit CRLF reject patterns — any reference to \r\n inside a
  // .matches / regex check, paired with throw/return earlier in the file.
  /\.matches\s*\([^)]*\\\\?r\\\\?n/,              // .matches(... \r\n ...)
  /\babort\s*\(\s*4\d\d/,                         // abort(4xx) earlier
  /\bres\s*\.\s*status\s*\(\s*4\d\d\b/,
  /\bthrow\s+new\s+\w+Exception\s*\([^)]*(?:header|crlf|newline)/i,
];

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  if (/\.java$/i.test(fp)) return 'java';
  if (/\.(?:php|phtml)$/i.test(fp)) return 'php';
  if (/\.go$/i.test(fp)) return 'go';
  if (/\.rb$/i.test(fp)) return 'rb';
  if (/\.cs$/i.test(fp)) return 'cs';
  if (/\.kt$/i.test(fp)) return 'kt';
  return null;
}

function _looksSanitizedAbove(raw, callLine) {
  const lines = raw.split('\n');
  const lo = Math.max(0, callLine - 30);
  const before = lines.slice(lo, callLine).join('\n');
  for (const p of SANITIZER_PATTERNS) if (p.test(before)) return true;
  return false;
}

export function scanResponseSplitting(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, (lang === 'py' || lang === 'rb') ? 'py' : undefined);
  if (!/\b(?:setHeader|addHeader|addIntHeader|setDateHeader|AddHeader|AppendHeader|response\s*\.\s*headers|response\s*\[|headers\s*\[|reply\s*\.\s*set|\.\s*Header\s*\(\s*\)\s*\.\s*(?:Set|Add)|Response\s*\.\s*Headers|\bheader\s*\()/i.test(code)) return [];
  const findings = [];
  const seen = new Set();
  for (const [plang, pat, label] of PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      // Use the LAST defined capture group as the header VALUE (php's pattern
      // captures the header NAME first, the value second).
      const value = ((m[m.length - 1] ?? m[1]) || '').trim();
      let tainted = TAINT_HINT_RE.test(value);
      // Handler-context heuristic: when `value` is a plain identifier that is a
      // parameter of the enclosing method/function, treat it as user-derived
      // (same "request-scope param" rule a real SAST tool applies). Covers the
      // single-file `void h(String v, … resp){ resp.setHeader("X", v); }` shape
      // for Java / Kotlin / C#.
      if (!tainted && (plang === 'java' || plang === 'kt' || plang === 'cs') && /^[A-Za-z_][\w]*$/.test(value)) {
        const before = code.slice(0, m.index);
        // Most recent signature `(...)` immediately followed by `{` — matches
        // Java/C# (`… name(params) {`) and Kotlin (`fun name(params) … {`).
        const sigRe = /\b(?:fun\s+\w+|[A-Za-z_][\w<>\[\],.\s]*\b\w+)\s*\(([^)]*)\)\s*(?::[^={]+)?(?:throws[^{]+)?\{/g;
        let sig = null, sm;
        while ((sm = sigRe.exec(before)) !== null) sig = sm;
        if (sig) {
          // Param name is the last token of each `Type name` / first of Kotlin `name: Type`.
          const params = sig[1].split(',').map((p) => {
            const t = p.trim();
            if (!t) return '';
            if (t.includes(':')) return t.split(':')[0].trim();      // Kotlin `name: Type`
            return (t.split(/\s+/).pop() || '').trim();              // Java/C# `Type name`
          });
          if (params.includes(value)) tainted = true;
        }
      }
      if (!tainted) continue;
      const line = _lineOf(raw, m.index);
      if (_looksSanitizedAbove(raw, line)) continue;
      const id = `response-splitting:${fp}:${line}:${label}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line,
        vuln: `HTTP Response Splitting / CRLF Injection (${label})`,
        severity: 'high',
        cwe: 'CWE-113',
        family: 'response-splitting',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation:
          'Strip or reject CR/LF characters before writing the value into a response header. ' +
          'Better: validate the value against a strict pattern (alnum + a small set of punctuation) and reject anything else. ' +
          'Java Servlet: prefer `response.setHeader(name, URLEncoder.encode(value, "UTF-8"))` or normalize via a helper. ' +
          'Node: `value.replace(/[\\r\\n]/g, "")` before `res.setHeader`. ' +
          'Django/Flask: assign through a setter that sanitizes; never raw `response[".."] = userInput`.',
        parser: 'RESPONSE-SPLITTING',
        confidence: 0.85,
      });
    }
  }
  return findings;
}
