// Stored / second-order taint (roadmap #2) — OPT-IN.
//
// Classic SAST blind spot: data written to a persistence store (DB / cache /
// file) by one request and read back by another is implicitly trusted, but if
// any user input was ever stored there it is still attacker-controlled. The
// result is stored XSS, second-order SQLi, etc. The engine's forward taint
// can't see across the persistence boundary.
//
// This detector flags the second-order SHAPE: a value READ from a store that
// flows into an injection sink without re-validation. It is inherently lower
// confidence than first-order taint (stored data is not ALWAYS attacker-
// controlled), so it is OFF by default and enabled with:
//
//   AGENTIC_SECURITY_STORED_TAINT=1
//
// Being opt-in, it cannot change default scan behavior (no default FPs/FNs).

import { blankComments } from './_comment-strip.js';

const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_RE = /\.py$/i;

// A read from a persistence store, capturing the assigned variable.
//   const row = await db.query(...)   |   row = collection.find_one(...)
const READ_ASSIGN = [
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[\w$.]*\b(?:query|find|findOne|findById|findAll|fetchRow|fetchAll|getItem|get|scan|select|aggregate|exec)\s*\(/g,
  /\b([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[\w$.]*\b(?:query|find|find_one|fetchone|fetchall|first|all|get_object_or_404)\s*\(/g,
];

// Injection sinks that, fed stored data, are second-order vulnerabilities.
function sinkPatternsFor(varName) {
  const v = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return [
    [new RegExp(`\\b(?:eval|exec|execSync|Function)\\s*\\([^)]*\\b${v}\\b`), 'CWE-94', 'code-injection'],
    [new RegExp(`\\.(?:innerHTML|outerHTML)\\s*=\\s*[^;\\n]*\\b${v}\\b`), 'CWE-79', 'xss'],
    [new RegExp(`\\bres(?:ponse)?\\s*\\.\\s*(?:send|write|end)\\s*\\([^)]*\\b${v}\\b`), 'CWE-79', 'xss'],
    [new RegExp(`\\b(?:query|execute|raw)\\s*\\([^)]*\\b${v}\\b[^)]*\\+`), 'CWE-89', 'sql-injection'],
    [new RegExp(`\\b(?:exec|execSync|spawn|system|popen)\\s*\\([^)]*\\b${v}\\b`), 'CWE-78', 'command-injection'],
  ];
}

const REVALIDATED = /\b(?:validate|sanitize|escape|encode|allow(?:list|ed)|schema\.\w*parse)\b/i;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanStoredTaint(fp, raw) {
  if (process.env.AGENTIC_SECURITY_STORED_TAINT !== '1') return [];
  if (!raw || raw.length > 500_000) return [];
  if (!JS_RE.test(fp) && !PY_RE.test(fp)) return [];

  const code = blankComments(raw, PY_RE.test(fp) ? 'py' : undefined);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();

  for (const re of READ_ASSIGN) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code))) {
      const varName = m[1];
      if (!varName) continue;
      const readLine = lineOf(code, m.index);
      // Search a forward window for the var reaching a sink, with no
      // re-validation in between.
      const winEnd = Math.min(lines.length, readLine + 20);
      const window = lines.slice(readLine, winEnd).join('\n');
      if (REVALIDATED.test(window)) continue;
      for (const [sinkRe, cwe, family] of sinkPatternsFor(varName)) {
        const sm = sinkRe.exec(window);
        if (!sm) continue;
        const sinkLine = readLine + window.substring(0, sm.index).split('\n').length;
        const key = `${sinkLine}:${family}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `stored-taint:${fp}:${sinkLine}:${family}`,
          severity: 'medium', file: fp, line: sinkLine,
          vuln: `Second-order / stored taint candidate (${family})`,
          cwe, family, parser: 'SAST', confidence: 0.4,
          description: `A value read from a persistence store ('${varName}') flows into a ${family} sink without re-validation. If any user input is ever written to that store, this is a second-order injection (e.g. stored XSS / second-order SQLi).`,
          remediation: 'Treat data read from a store as untrusted: validate/encode it at the sink exactly as you would direct request input. Do not rely on validation performed at write time.',
        });
        break; // one sink class per read is enough
      }
    }
  }
  return findings;
}
