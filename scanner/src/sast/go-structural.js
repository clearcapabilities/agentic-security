// Go structural (taint-independent) injection detectors — PRD Tier 1 (Go recall).
//
// Go handler FNs: user input from c.Query / r.URL.Query().Get is built into a
// sink via fmt.Sprintf or string concat (Go has no string templates). That
// shape is the vulnerability regardless of variable names. Parameterized
// queries (`db.Query("… ?", x)`) and canonicalized paths have no Sprintf/concat
// in the sink argument, so they don't match.

import { blankComments } from './_comment-strip.js';

const lineOf = (raw, idx) => raw.substring(0, idx).split('\n').length;

export function scanGoStructural(fp, raw) {
  if (!/\.go$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const emit = (key, line, meta) => {
    const id = `go-struct-${key}:${fp}:${line}`;
    if (seen.has(id)) return;
    seen.add(id);
    findings.push({
      id, file: fp, line, vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
      family: meta.family, parser: 'GO', confidence: meta.confidence ?? 0.72,
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200), remediation: meta.remediation,
    });
  };

  // SQL injection: a database/sql query method built with fmt.Sprintf or concat.
  const SQL_RE = /\.(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext)\s*\(\s*(?:fmt\.Sprintf\s*\(|"[^"\n]*"\s*\+)/g;
  let m;
  while ((m = SQL_RE.exec(code))) emit('sqli', lineOf(code, m.index), {
    vuln: 'SQL Injection — query built with fmt.Sprintf / concat (Go)',
    severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', confidence: 0.75,
    remediation: 'Use parameter placeholders: db.Query("… WHERE name = ?", name). Never build SQL with fmt.Sprintf or string concatenation.',
  });

  // Path traversal: an os/ioutil file op built with concat or fmt.Sprintf.
  const PATH_RE = /\b(?:os\.Open|os\.OpenFile|os\.ReadFile|os\.Create|ioutil\.ReadFile|ioutil\.WriteFile)\s*\(\s*(?:"[^"\n]*"\s*\+|fmt\.Sprintf\s*\()/g;
  while ((m = PATH_RE.exec(code))) emit('path', lineOf(code, m.index), {
    vuln: 'Path Traversal — file path built with concat / fmt.Sprintf (Go)',
    severity: 'high', cwe: 'CWE-22', family: 'path-traversal', confidence: 0.7,
    remediation: 'Strip the path with filepath.Base and assert containment: want := filepath.Join(base, filepath.Base(name)); if !strings.HasPrefix(filepath.Clean(want), base) { reject }.',
  });

  // Insecure deserialization: encoding/gob decoding attacker-controlled bytes
  // into an interface{} / any target — gob will instantiate registered concrete
  // types, a deserialization gadget surface. Gated on encoding/gob being used.
  if (/\bencoding\/gob\b|\bgob\.NewDecoder\b/.test(code)) {
    const GOB_RE = /\bgob\.NewDecoder\s*\([\s\S]*?\)\s*\.\s*Decode\s*\(|\b\w+\s*:?=\s*gob\.NewDecoder\s*\(/g;
    while ((m = GOB_RE.exec(code))) emit('gob-deser', lineOf(code, m.index), {
      vuln: 'Insecure Deserialization — encoding/gob decoding untrusted input (Go)',
      severity: 'high', cwe: 'CWE-502', family: 'insecure-deserialization', confidence: 0.6,
      remediation: 'Do not gob-decode data from an untrusted source — gob instantiates registered concrete types and is not designed for adversarial input. Use a schema-validated format (JSON with a fixed struct, protobuf) and validate before use.',
    });
  }

  return findings;
}
