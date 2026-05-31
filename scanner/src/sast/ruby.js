import { blankComments } from './_comment-strip.js';
// Ruby-specific detectors. Targets Rails idioms and the eval-family methods
// that make Ruby code easy to compromise when fed untrusted input.
//
//   - User input into eval / instance_eval / class_eval / module_eval
//   - send / public_send with a user-controlled method name
//   - Marshal.load on user input
//   - YAML.load (not safe_load) on user input
//   - ERB.new(...).result on user input
//   - Open / `` (backtick) with user input (command injection)
//   - Rails: attributes = params (without strong_params)
//   - Open::URI.open(user_url) — SSRF
//   - File.read(params[...]) — path traversal

const RE = {
  evalFamily: /\b(?:eval|instance_eval|class_eval|module_eval)\s*\(?\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  send: /\.(?:send|public_send)\s*\(\s*(?:params|request|@\w+\.params)\b/g,
  marshalLoad: /\bMarshal\s*\.\s*load\s*\(\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  yamlUnsafe: /\bYAML\s*\.\s*load\s*\(\s*(?:params|request|@\w+\.params|cookies|session)\b/g,
  erbResult: /\bERB\.new\s*\(\s*(?:params|request|@\w+\.params)\b[^)]*\)\s*\.\s*result/g,
  backtick: /`[^`]*#\{[^}]*\b(?:params|request|@\w+\.params)\b[^}]*\}/g,
  systemUser: /\b(?:system|exec|Open3\.capture\d*|IO\.popen)\s*\(\s*[^)]*\b(?:params|request|@\w+\.params)\b/g,
  attributesEq: /\.\s*attributes\s*=\s*params\b(?!\s*\.permit)/g,
  openSsrf: /\b(?:open|URI\.open|URI\.parse\([^)]*\)\.read)\s*\(\s*(?:params|request|@\w+\.params)\b/g,
  fileRead: /\bFile\s*\.\s*(?:read|open|new|readlines)\s*\(\s*params\s*\[/g,
  // Structural (taint-independent): an ActiveRecord query or shell command
  // built with string interpolation (#{...}) or concat is the injection shape
  // regardless of whether the value is `params` or a local variable that came
  // from params — the existing rules above require the literal `params` token
  // on the sink line, which misses `name = params[:x]; where("... #{name}")`.
  sqlInjectionStructural: /\.(?:where|find_by_sql|having|order|group|joins|select|from|pluck|update_all|delete_all|exec_query|execute|select_all|select_value|find_by)\s*\(\s*(?:"[^"\n]*#\{|['"][^'"\n]*['"]\s*\+)/g,
  cmdInjectionStructural: /(?:`[^`\n]*#\{|\b(?:system|exec)\s*\(\s*"[^"\n]*#\{|\bIO\.popen\s*\(\s*"[^"\n]*#\{|\b(?:system|exec)\s*\(\s*['"][^'"\n]*['"]\s*\+)/g,
  // Structural path traversal: File/IO op whose path is built by interpolation
  // (#{...}) or concat. `File.read("/data/" + name)` routes through a local var
  // so the `params[`-on-sink fileRead rule misses it. Containment-guarded forms
  // (File.expand_path + start_with?) are dropped by engine.js dropGuardedFindings.
  pathTraversalStructural: /\b(?:File|IO)\s*\.\s*(?:read|open|new|readlines|binread|write|foreach)\s*\(\s*(?:"[^"\n]*#\{|['"][^'"\n]*['"]\s*\+)/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanRuby(fp, raw) {
  if (!/\.rb$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  // Ruby's comment char is # (same as Python) — use the py stripper.
  const code = blankComments(raw, 'py');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      const meta = {
        evalFamily: {
          vuln: 'Code Injection: eval/instance_eval/class_eval on user-controlled input',
          severity: 'critical', cwe: 'CWE-94',
          remediation: 'Never call eval on user input — there is no safe sanitization. Replace with explicit branching on enumerated values, a method dispatch table (whitelist), or a parser for a constrained DSL.',
        },
        send: {
          vuln: 'Method Reflection: send/public_send with user-controlled method name',
          severity: 'high', cwe: 'CWE-470',
          remediation: 'Validate the method name against an explicit whitelist before sending. `params[:action]` straight into `send` lets the client invoke any method on the receiver, including private ones with `send`.',
        },
        marshalLoad: {
          vuln: 'Insecure Deserialization: Marshal.load on user input',
          severity: 'critical', cwe: 'CWE-502',
          remediation: 'Marshal is unsafe by design — never use it on data crossing a trust boundary. Replace with JSON or msgpack with an explicit schema.',
        },
        yamlUnsafe: {
          vuln: 'Insecure Deserialization: YAML.load on user input',
          severity: 'critical', cwe: 'CWE-502',
          remediation: 'Replace `YAML.load(input)` with `YAML.safe_load(input, permitted_classes: [Symbol], aliases: true)` — the default `load` will instantiate arbitrary Ruby classes from a crafted document (same risk class as Marshal).',
        },
        erbResult: {
          vuln: 'Server-Side Template Injection: ERB.new(user_template).result',
          severity: 'critical', cwe: 'CWE-94',
          remediation: 'Never feed a user-supplied string into ERB. Predefine templates server-side; the client may pass *values*, never the template body.',
        },
        backtick: {
          vuln: 'Command Injection: backtick command interpolates request data',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `Open3.capture2(["cmd", arg1, arg2])` with an array form so the shell does not parse anything. Backticks and `system("cmd #{params[...]}")` are pure shell injection.',
        },
        systemUser: {
          vuln: 'Command Injection: system/exec/Open3 with user-controlled input',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use the array form: `system(["cmd", arg])`. The string form lets the shell parse — any quoting trick wins.',
        },
        attributesEq: {
          vuln: 'Mass Assignment: model.attributes = params (no strong_params)',
          severity: 'high', cwe: 'CWE-915',
          remediation: 'Use `params.require(:user).permit(:name, :email)` — explicit allow-list. Assigning raw `params` lets the client set fields the controller never intended (admin: true, role: ...).',
        },
        openSsrf: {
          vuln: 'SSRF: open/URI.open with user-controlled URL',
          severity: 'high', cwe: 'CWE-918',
          remediation: 'Resolve and validate the host against an allow-list before fetching. `open(params[:url])` is also a path-traversal vector under older Ruby (open-uri inherits Kernel#open semantics).',
        },
        fileRead: {
          vuln: 'Path Traversal: File.read/open with user-controlled path',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize the path and verify it stays under an allowed base: `path = File.expand_path(File.join(base, name)); raise unless path.start_with?(base)`.',
        },
        sqlInjectionStructural: {
          vuln: 'SQL Injection: ActiveRecord query built with string interpolation / concat',
          severity: 'critical', cwe: 'CWE-89',
          remediation: 'Use the parameterized form: `User.where("name = ?", name)` or `where(name: name)`. Never interpolate (`#{...}`) or concatenate values into a SQL fragment.',
        },
        cmdInjectionStructural: {
          vuln: 'Command Injection: shell command built with string interpolation / concat',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `Open3.capture2("cmd", arg1, arg2)` with separate arguments (no shell). Backticks and `system("... #{x}")` run through the shell.',
        },
        pathTraversalStructural: {
          vuln: 'Path Traversal: File/IO operation built with interpolated/concatenated path',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize and assert containment: `path = File.expand_path(File.join(base, name)); raise unless path.start_with?(base)`. Never interpolate/concatenate request input straight into a file path.',
        },
      }[key];
      push({
        id: `ruby-${key}:${fp}:${line}`,
        file: fp, line,
        vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: meta.remediation,
        parser: 'RUBY',
        confidence: 0.80,
      });
    }
  }
  return findings;
}
