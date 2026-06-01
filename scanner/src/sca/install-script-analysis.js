// R9 (PRD §5) — static behavioral analysis of package install hooks.
//
// The last several years of high-profile supply-chain attacks (event-stream,
// ua-parser-js, the xz backdoor's build step) ran their payload from a package
// LIFECYCLE script — preinstall/install/postinstall — that fetched and executed
// remote code, decoded an obfuscated blob, or exfiltrated environment secrets.
// Typosquat/dep-confusion (dep-confusion.js) catches the NAME; this catches the
// install-time BEHAVIOR, deterministically, on any package.json we can see.
//
// Precision-first: legitimate hooks (node-gyp rebuild, husky install,
// patch-package, electron-builder, "node ./scripts/x.js") do none of these, so
// they don't match. We only flag inline dangerous shapes.

const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly'];

const DANGEROUS = [
  { id: 'download-exec', cwe: '829', sev: 'critical',
    re: /\b(?:curl|wget|fetch)\b[^\n|&;]*?(?:https?:\/\/|\$\{?[A-Za-z_])[^\n|]*?[|&;]{1,2}\s*(?:sh|bash|zsh|node|python3?|ruby|perl)\b/i,
    why: 'downloads and pipes remote content directly into an interpreter (remote code execution at install time)' },
  { id: 'base64-exec', cwe: '506', sev: 'critical',
    re: /base64\s+(?:-d|--decode|-D)[^\n]*\|\s*(?:sh|bash|zsh|node|python3?)\b/i,
    why: 'decodes a base64 blob and executes it (obfuscated payload)' },
  { id: 'eval-decode', cwe: '506', sev: 'critical',
    re: /\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|require\(\s*['"]child_process)/i,
    why: 'eval of a decoded/obfuscated string or child_process (obfuscated payload)' },
  { id: 'inline-node-eval', cwe: '94', sev: 'high',
    // Only when the inline program does something dangerous — network I/O,
    // process spawn, or eval/decode. A bare `node -e "const fs=require('fs')…"`
    // (common in legitimate build hooks, incl. this repo's) must NOT match.
    re: /\bnode\s+(?:--eval|-e)\b[^\n]*(?:require\(\s*['"](?:https?|http2|child_process|net|dns|tls)\b|https?:\/\/|\batob\b|Buffer\.from\s*\([^)]*base64|\beval\s*\()/i,
    why: 'runs an inline node program that performs network I/O, spawns a process, or evals a decoded blob' },
  { id: 'env-exfil', cwe: '200', sev: 'high',
    re: /(?:process\.env|printenv|env\b|\$[A-Z_]{3,})[^\n]*(?:curl|wget|nc\b|netcat|https?:\/\/)[^\n]*(?:\||>|<)/i,
    why: 'reads environment variables and pipes them to a network command (credential exfiltration)' },
  { id: 'cred-read', cwe: '522', sev: 'high',
    re: /(?:\.npmrc|id_rsa|\.aws\/credentials|\.ssh\/|\.netrc|\.docker\/config)/i,
    why: 'reads credential/secret files from an install hook' },
];

// Obfuscation heuristic: a long hex/base64 blob embedded in the hook string.
const OBFUSCATION = /(?:\\x[0-9a-f]{2}){12,}|[A-Za-z0-9+/]{120,}={0,2}/;

export function scanInstallScripts(fp, raw) {
  if (typeof raw !== 'string' || !raw) return [];
  const base = fp.split('/').pop();
  if (base !== 'package.json') return [];
  let pkg;
  try { pkg = JSON.parse(raw); } catch { return []; }
  const scripts = pkg && pkg.scripts;
  if (!scripts || typeof scripts !== 'object') return [];
  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();
  for (const hook of LIFECYCLE_HOOKS) {
    const cmd = scripts[hook];
    if (typeof cmd !== 'string' || !cmd) continue;
    // Locate the hook's line for attribution.
    const li = lines.findIndex(l => new RegExp(`["']${hook}["']\\s*:`).test(l));
    const line = li >= 0 ? li + 1 : 1;
    const checks = [...DANGEROUS];
    if (OBFUSCATION.test(cmd)) checks.push({ id: 'obfuscated-blob', cwe: '506', sev: 'high', re: /.*/, why: 'embeds a long obfuscated (hex/base64) blob' });
    for (const d of checks) {
      if (!d.re.test(cmd)) continue;
      const key = `${line}:${d.id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `install-script:${fp}:${hook}:${d.id}`,
        severity: d.sev,
        file: fp,
        line,
        vuln: `Malicious-looking install hook — \`${hook}\` ${d.id}`,
        cwe: d.cwe,
        family: 'malicious-install-script',
        parser: 'SCA-INSTALL',
        description: `The \`${hook}\` lifecycle script ${d.why}. Script: ${cmd.slice(0, 160)}`,
        remediation: `Audit the \`${hook}\` script in ${base}. Lifecycle hooks should not fetch+exec remote code, decode/eval blobs, or read secrets. If this is a dependency's package.json, treat the package as suspicious and pin/replace it; install with --ignore-scripts where possible.`,
      });
    }
  }
  return findings;
}
