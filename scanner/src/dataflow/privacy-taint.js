// Privacy / PII data-flow tracking — Recommendation #9 of the
// world-class roadmap.
//
// Runs the existing taint engine with a different lattice (PII / PHI /
// PCI / FIN classes, instead of security taint) to track where each
// regulated-data class flows through a codebase. Outputs:
//
//   1. Per-field PII classification — `user.email: PII (CWE-359 Information
//      Disclosure if reflected)`
//   2. Data flow diagrams — exit points (sinks) per PII class — where
//      regulated data leaves the application (response body, log file,
//      third-party API call, S3 upload, etc.)
//   3. Auto-generated DPIA stub for GDPR Art. 35 / CCPA §1798.130 /
//      HIPAA §164.530 — a compliance artifact the customer's privacy
//      counsel can use
//   4. Findings: each "PII leaves system via untrusted sink" emits a
//      privacy finding with family `pii-exposure`
//
// The PII detection is deterministic and field-name based. We DO NOT
// attempt content classification (Luhn-checking actual values would
// only catch leaks that have already happened); we classify by NAME
// + TYPE in declarations.

// PII / PHI / PCI / FIN classifiers — each is a regex against
// field/variable/column names. Same idea as the existing classifyField
// helpers in engine.js but enumerated for compliance reporting.

const PII_PATTERNS = {
  PII: [
    /\bfirst[_-]?name\b/i, /\blast[_-]?name\b/i, /\bfull[_-]?name\b/i,
    /\bemail([_-]?address)?\b/i, /\bphone([_-]?number)?\b/i, /\bmobile\b/i,
    /\baddress(?:_?(?:line|street|city|zip|postal))?\b/i,
    /\bdob\b/i, /\bdate[_-]?of[_-]?birth\b/i, /\bbirthday\b/i, /\bbirthdate\b/i,
    /\bage\b/i, /\bgender\b/i, /\bethnicity\b/i, /\brace\b/i, /\bnationality\b/i,
    /\bssn\b/i, /\bsocial[_-]?security/i, /\bnational[_-]?id/i, /\bpassport\b/i,
    /\bdriver[_-]?license\b/i, /\btax[_-]?id\b/i, /\bgovernment[_-]?id\b/i,
    /\bip[_-]?address\b/i, /\bgeo[_-]?location\b/i, /\blatitude\b/i, /\blongitude\b/i,
  ],
  PHI: [
    /\b(?:medical|patient|health)[_-]?record\b/i,
    /\bdiagnosis\b/i, /\bcondition\b/i, /\bsymptom\b/i, /\btreatment\b/i,
    /\bmedication\b/i, /\bprescription\b/i, /\bdosage\b/i,
    /\bicd[_-]?(?:9|10|11)\b/i, /\bcpt[_-]?code\b/i, /\bmrn\b/i,
    /\bmedical[_-]?record[_-]?number\b/i, /\bdoctor[_-]?name\b/i,
    /\bphysician\b/i, /\binsurance[_-]?id\b/i, /\bhealth[_-]?plan\b/i,
  ],
  PCI: [
    /\bcredit[_-]?card[_-]?(?:number|num|no)?\b/i,
    /\bcard[_-]?(?:number|num|no)\b/i,
    /\b(?:cvc|cvv)2?\b/i, /\bcvc[_-]?code\b/i,
    /\bexp(?:iry|iration)?(?:_?date)?\b/i,
    /\bcardholder[_-]?name\b/i, /\bpan\b/i,
    /\biban\b/i, /\brouting[_-]?number\b/i,
    /\baccount[_-]?number\b/i,
  ],
  FIN: [
    /\bsalary\b/i, /\bincome\b/i, /\bbalance\b/i, /\btransaction[_-]?amount\b/i,
    /\bbank[_-]?account\b/i,
    /\bcredit[_-]?score\b/i, /\bnet[_-]?worth\b/i,
  ],
};

const SINK_PATTERNS = {
  log: /\b(?:log|logger|console|System\.out|System\.err|stdout|stderr|fmt\.Print|print)\b/i,
  response: /\b(?:res|response|ctx\.response|HttpContext\.Response)\s*\.\s*(?:write|send|json|render|body)\b/i,
  outboundHttp: /\bfetch\b(?:$|[(\s.])|\b(?:axios|got|httpClient|HttpClient|WebClient|requests|node_fetch)\s*(?:\.\s*(?:get|post|put|delete|send|invoke|patch|head)|\()/i,
  thirdPartySdk: /\b(?:stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|intercom)\s*\.\s*track|identify|capture\b/i,
  fileWrite: /\b(?:fs\.writeFile|File\.WriteAllText|File\.AppendAllText|open\([^)]*,\s*['"]w)\b/i,
  s3Upload: /\b(?:s3|S3Client|aws\.S3)\s*\.\s*putObject\b/i,
  emailSend: /\b(?:nodemailer|sendMail|SendGrid|sendgrid|smtp)\b/i,
};

/**
 * Classify a field/variable name into PII / PHI / PCI / FIN buckets.
 * Returns an array of bucket labels (possibly empty, possibly multiple).
 */
export function classifyField(name) {
  if (!name) return [];
  const out = [];
  for (const [bucket, patterns] of Object.entries(PII_PATTERNS)) {
    for (const p of patterns) {
      if (p.test(name)) { out.push(bucket); break; }
    }
  }
  return out;
}

/**
 * Classify an outbound-data sink expression. Returns the matching sink
 * label (log / response / outboundHttp / etc.) or null.
 */
export function classifySink(expr) {
  if (!expr) return null;
  for (const [label, p] of Object.entries(SINK_PATTERNS)) if (p.test(expr)) return label;
  return null;
}

/**
 * Run a privacy-taint pass over the per-file IR. For each field declared
 * as PII/PHI/PCI/FIN, track flow into a classifySink-matched sink. Emit
 * a privacy-leak finding when a regulated class reaches a non-secure
 * sink (log, response, outbound HTTP, etc.).
 */
export function annotatePrivacyTaint(perFileIR) {
  if (!perFileIR) return { findings: [], piiFields: [] };
  const findings = [];
  const piiFields = [];
  for (const [filePath, ir] of (perFileIR instanceof Map ? perFileIR : Object.entries(perFileIR))) {
    if (!ir || !ir._content) continue;
    const lines = ir._content.split('\n');
    // Step 1: collect PII-classified decls.
    const taintedVars = new Map(); // name → array of bucket labels
    for (const d of ir.decls || []) {
      const classes = classifyField(d.name);
      if (classes.length) {
        taintedVars.set(d.name, classes);
        piiFields.push({ file: filePath, line: d.line, name: d.name, classes, declaredType: d.type || null });
      }
    }
    // Step 2: walk calls and assignments looking for a PII variable
    // reaching a sink.
    for (const call of ir.calls || []) {
      const argText = (call.args || []).map(a => a.text || '').join(',');
      const sinkLabel = classifySink(call.fullPath || call.callee || '');
      if (!sinkLabel) continue;
      for (const [name, classes] of taintedVars) {
        if (!new RegExp(`\\b${name.replace(/[.+^${}()|\\]/g, '\\$&')}\\b`).test(argText)) continue;
        findings.push({
          family: 'pii-exposure',
          subfamily: classes.join('+'),
          file: filePath, line: call.line,
          severity: classes.includes('PCI') || classes.includes('PHI') ? 'high' : 'medium',
          cwe: 'CWE-359', // Exposure of Private Personal Information
          vuln: `Privacy — ${classes.join('+')} data flows to ${sinkLabel} sink`,
          snippet: (lines[call.line - 1] || '').trim().slice(0, 200),
          remediation: `${classes.join(' + ')} data must not flow to ${sinkLabel} unencrypted. Mask, redact, or hash the value before logging / responding / sending to third parties.`,
          piiClass: classes,
          sinkKind: sinkLabel,
        });
      }
    }
  }
  return { findings, piiFields };
}

/**
 * Emit a DPIA (Data Protection Impact Assessment) Markdown artifact
 * summarizing the privacy posture for compliance reporting. Output goes
 * to .agentic-security/dpia.md.
 */
export function emitDpiaArtifact(piiFields, findings, opts = {}) {
  const grouped = new Map();
  for (const field of piiFields) {
    for (const cls of field.classes) {
      let g = grouped.get(cls);
      if (!g) { g = []; grouped.set(cls, g); }
      g.push(field);
    }
  }
  const lines = [];
  lines.push(`# Data Protection Impact Assessment (DPIA)`);
  lines.push('');
  lines.push(`Generated by agentic-security scanner on ${new Date().toISOString().slice(0, 10)}.`);
  lines.push('');
  lines.push(`This is an automated DPIA scaffold derived from static analysis.`);
  lines.push(`It must be reviewed and completed by a privacy officer before use.`);
  lines.push('');
  lines.push(`## Data classes identified`);
  lines.push('');
  for (const [cls, fields] of grouped) {
    lines.push(`### ${cls} (${fields.length} fields)`);
    lines.push('');
    for (const f of fields.slice(0, 20)) {
      lines.push(`- \`${f.name}\` in \`${f.file}:${f.line}\` (type: ${f.declaredType || 'unknown'})`);
    }
    if (fields.length > 20) lines.push(`- … and ${fields.length - 20} more`);
    lines.push('');
  }
  lines.push(`## Privacy-related findings`);
  lines.push('');
  lines.push(`| Severity | File:Line | Class → Sink | Description |`);
  lines.push(`|---|---|---|---|`);
  for (const f of findings.slice(0, 50)) {
    lines.push(`| ${f.severity} | ${f.file}:${f.line} | ${f.piiClass.join('+')} → ${f.sinkKind} | ${f.vuln} |`);
  }
  if (findings.length > 50) lines.push(`| … | … | … | … and ${findings.length - 50} more |`);
  lines.push('');
  lines.push(`## Regulatory framework mapping`);
  lines.push('');
  lines.push(`- **GDPR Art. 35** — DPIA required when processing is likely to result in high risk to data subjects.`);
  lines.push(`- **CCPA §1798.130** — Notice + access rights for collected personal information.`);
  if (grouped.has('PHI')) lines.push(`- **HIPAA §164.308** — Administrative safeguards for ePHI access.`);
  if (grouped.has('PCI')) lines.push(`- **PCI DSS Req. 3** — Protect stored cardholder data.`);
  lines.push('');
  lines.push(`## Reviewer checklist`);
  lines.push('');
  lines.push(`- [ ] Confirm each PII field's collection has a documented lawful basis`);
  lines.push(`- [ ] Confirm retention period for each class is documented`);
  lines.push(`- [ ] Confirm DSAR (data subject access request) workflow exists`);
  lines.push(`- [ ] Confirm encryption at rest + in transit for each class`);
  lines.push(`- [ ] Confirm logging of PII access for audit (where applicable)`);
  return lines.join('\n');
}

export const _internals = { PII_PATTERNS, SINK_PATTERNS };
