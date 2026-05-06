// Report writers — JSON / Markdown / SARIF.
import * as crypto from 'node:crypto';

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_TO_SARIF = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'none' };

function fingerprint(f){
  const s = `${f.file}:${f.line||f.source?.line||0}:${f.vuln||f.type||''}`;
  return crypto.createHash('sha256').update(s).digest('hex').slice(0, 16);
}

export function normalizeFindings(scan){
  const out = [];
  for (const f of (scan.findings||[])) {
    out.push({
      id: f.id || fingerprint(f),
      kind: f.isCrossFile ? 'sast' : (f.kind || 'sast'),
      severity: f.severity || 'medium',
      vuln: f.vuln || f.type,
      cwe: f.cwe || null,
      stride: f.stride || null,
      file: f.file,
      line: f.line || f.source?.line || f.sink?.line || 0,
      snippet: f.snippet || f.source?.snippet || f.sink?.snippet || '',
      fix: f.fix ? { description: f.fix, code: f.code || '' } : null,
      reachable: f.reachable ?? null,
      exploitability: f.exploitabilityScore ?? null,
      dataClasses: f.dataClasses || [],
    });
  }
  for (const s of (scan.secrets||[])) {
    out.push({
      id: s.id || fingerprint(s),
      kind: 'secret',
      severity: s.severity || 'high',
      vuln: s.vuln || 'Hardcoded Secret',
      cwe: s.cwe || 'CWE-798',
      stride: s.stride || 'Information Disclosure',
      file: s.file, line: s.line, snippet: s.snippet || '',
      masked: s.masked || null,
      fix: s.fix ? { description: s.fix, code: s.code || '' } : null,
    });
  }
  for (const sc of (scan.supplyChain||[])) {
    out.push({
      id: fingerprint(sc),
      kind: 'sca',
      severity: sc.severity || 'high',
      vuln: sc.vuln || sc.advisory || 'Vulnerable Dependency',
      cwe: sc.cwe || null,
      stride: null,
      file: sc.filePath || sc.file || 'package.json',
      line: 0,
      ecosystem: sc.ecosystem,
      package: sc.name,
      version: sc.version,
      cveAliases: sc.cveAliases || [],
      osvId: sc.osvId || null,
      advisory: sc.advisory || sc.description || '',
      fixedIn: sc.range || null,
    });
  }
  return out.sort((a,b)=> (SEV_RANK[a.severity]??9) - (SEV_RANK[b.severity]??9));
}

export function toJSON(scan, meta={}){
  return {
    scanId: meta.scanId || crypto.randomUUID(),
    startedAt: meta.startedAt || new Date().toISOString(),
    durationMs: meta.durationMs || 0,
    scanned: { files: scan.filesScanned||0, lines: scan.linesScanned||0 },
    findings: normalizeFindings(scan),
    routes: scan.routes || [],
    components: (scan.components||[]).map(c=>({
      ecosystem: c.ecosystem, name: c.name, version: c.version,
      reachable: c.reachable, hasVulns: c.hasVulns, isDeprecated: c.isDeprecated,
      latestVersion: c.latestVersion, license: c.license,
    })),
  };
}

export function toMarkdown(scan, meta={}){
  const findings = normalizeFindings(scan);
  const lines = ['# Agentic Security — Scan Report', ''];
  lines.push(`**Files scanned:** ${scan.filesScanned||0}    **Findings:** ${findings.length}    **Generated:** ${meta.startedAt||new Date().toISOString()}`);
  lines.push('');
  const bySev = {};
  for (const f of findings) (bySev[f.severity] ||= []).push(f);
  for (const sev of ['critical','high','medium','low','info']) {
    if (!bySev[sev]) continue;
    lines.push(`## ${sev.toUpperCase()} (${bySev[sev].length})`);
    lines.push('');
    lines.push('| File:Line | Vulnerability | CWE | Fix |');
    lines.push('|---|---|---|---|');
    for (const f of bySev[sev]) {
      const fix = f.fix?.description || '';
      lines.push(`| \`${f.file}:${f.line}\` | ${f.vuln} | ${f.cwe||'—'} | ${fix.replace(/\|/g,'\\|').slice(0,140)} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export function toSARIF(scan, meta={}){
  const findings = normalizeFindings(scan);
  const ruleMap = new Map();
  for (const f of findings) if (f.vuln && !ruleMap.has(f.vuln)) ruleMap.set(f.vuln, {
    id: f.vuln.replace(/[^a-zA-Z0-9]/g, '_'),
    name: f.vuln,
    shortDescription: { text: f.vuln },
    fullDescription: { text: f.fix?.description || f.vuln },
    helpUri: f.cwe ? `https://cwe.mitre.org/data/definitions/${f.cwe.replace(/[^0-9]/g,'')}.html` : undefined,
    properties: { tags: [f.cwe, f.stride].filter(Boolean) },
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'agentic-security', version: '0.1.0', informationUri: 'https://github.com/clearcapabilities/agentic-security', rules: [...ruleMap.values()] }},
      results: findings.map(f => ({
        ruleId: f.vuln ? f.vuln.replace(/[^a-zA-Z0-9]/g, '_') : 'unknown',
        level: SEV_TO_SARIF[f.severity] || 'warning',
        message: { text: f.fix?.description || f.vuln || 'Security finding' },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, f.line||1) } } }],
        partialFingerprints: { primaryLocationLineHash: f.id },
      })),
    }],
  };
}

const SEV_COLOR = { critical: '\x1b[91m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[32m', info: '\x1b[36m' };
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

export function toCLI(scan, { verbose=false, color=true }={}){
  const findings = normalizeFindings(scan);
  const lines = [];
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  lines.push(c(BOLD+`Agentic Security — ${findings.length} finding(s) across ${scan.filesScanned||0} file(s)`, ''));
  lines.push('');
  for (const f of findings) {
    const sevTag = c(`[${f.severity.toUpperCase()}]`, SEV_COLOR[f.severity]||'');
    lines.push(`${sevTag} ${c(f.cwe||'    ', DIM)}  ${f.file}:${f.line}  ${BOLD}${f.vuln}${RESET}`);
    if (f.masked) lines.push(`        ${c('value:', DIM)} ${f.masked}`);
    if (verbose && f.fix?.description) {
      lines.push(`        ${c('fix:', DIM)} ${f.fix.description}`);
      if (f.fix.code) for (const ln of f.fix.code.split('\n').slice(0, 6)) lines.push(`           ${c(ln, DIM)}`);
    }
  }
  lines.push('');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
  lines.push(`${c('Critical:', SEV_COLOR.critical)} ${counts.critical}    ${c('High:', SEV_COLOR.high)} ${counts.high}    ${c('Medium:', SEV_COLOR.medium)} ${counts.medium}    ${c('Low:', SEV_COLOR.low)} ${counts.low}    ${c('Info:', SEV_COLOR.info)} ${counts.info}`);
  return lines.join('\n');
}

export function exitCodeFor(scan){
  const findings = normalizeFindings(scan);
  if (findings.some(f=>f.severity==='critical')) return 3;
  if (findings.some(f=>f.severity==='high')) return 2;
  if (findings.some(f=>f.severity==='medium' || f.severity==='low')) return 1;
  return 0;
}
