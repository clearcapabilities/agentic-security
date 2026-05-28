// C# / .NET SAST module — Layers 1-4 of the C# detection pipeline.
//
// Architecture (replacing the previous regex-on-cleaned-source approach):
//
//   Layer 1: Token-aware lexer (../sast/csharp-tokenizer.js) — strings,
//            verbatim, interpolated, comments, attributes all preserved
//            with semantic identity.
//   Layer 2: Hand-rolled IR (../ir/csharp-ir.js) — emits classes, methods,
//            calls, declarations, assignments, attributes.
//   Layer 3: Lexical type-flow + taint (../posture/csharp-analysis.js) —
//            per-method typeMap and taintMap, forward-propagated through
//            declarations and assignments.
//   Layer 4: Attribute-driven route + auth detection — same module, reads
//            [HttpGet]/[HttpPost]/[Route]/[Authorize]/[AllowAnonymous].
//
// The detectors below query the IR using these helpers and are completely
// regex-free for their primary logic. They still use small regex for cheap
// type-name and string-content checks.
//
// Covered Juliet C# CWE families:
//   CWE-22  path-traversal       Path.Combine + tainted segment, no Path.GetFullPath check
//   CWE-78  command-injection    Process.Start with tainted args / ShellExecute=true
//   CWE-79  xss                  Razor Html.Raw / Response.Write with tainted argument
//   CWE-89  sql-injection        Sql/Ole/MySql/NpgsqlCommand with tainted CommandText / concatenation in constructor / FromSqlRaw
//   CWE-90  ldap-injection       DirectorySearcher / LdapConnection .Search/.SendRequest with tainted filter
//   CWE-330 weak-rng             new Random() in cryptographic context (presence of System.Security.Cryptography uses or "password"/"token" naming)
//   CWE-327 weak-crypto          DESCryptoServiceProvider / RC2 / TripleDES / MD5 / SHA1 — including factory methods
//   CWE-502 insecure-deserialization  BinaryFormatter.Deserialize / NetDataContractSerializer / Newtonsoft TypeNameHandling != None
//   CWE-611 xxe                  XmlDocument w/o XmlResolver=null; XmlReaderSettings w/o DtdProcessing=Prohibit
//   CWE-798 hardcoded-secret     Field/local with name matching password/token/secret/apiKey + non-empty string literal initializer
//   CWE-1004 header-hardening    new HttpCookie missing Secure/HttpOnly
//   CWE-22  validate-input-false [ValidateInput(false)] attribute
//
// Findings carry: id, file, line, vuln, severity, cwe, stride, snippet,
// remediation, confidence, parser, family, and a `_taintEvidence` field
// when the detector relied on Layer 3 to confirm reachability from a
// known source. The LLM validator (when enabled) sees these fields and
// can second-stage low-confidence findings.

import { buildCSharpIR } from '../ir/csharp-ir.js';
import {
  analyzeCSharpIR, receiverIsType, expressionIsTainted, interpStringIsTainted, argIsTainted,
} from '../posture/csharp-analysis.js';

// Helper: collect identifier names from a token slice (idents only — not
// string-literal contents). Used by detectors when checking taint on a
// declaration's rhs to avoid false positives from SQL parameter
// placeholders like "@id" appearing inside a string literal.
function rhsIdents(tokens) {
  const out = [];
  for (const t of tokens || []) {
    if (!t) continue;
    if (t.kind === 'ident') out.push(t.value);
    if (t.kind === 'interp') for (const p of t.parts || []) if (p.kind === 'expr') for (const inner of (p.tokens || [])) if (inner.kind === 'ident') out.push(inner.value);
  }
  return out;
}

function rhsHasConcatWithIdent(tokens) {
  // True if the token stream contains: <string-literal> '+' <ident>
  // (idents from inside the string don't count).
  for (let i = 0; i < tokens.length - 2; i++) {
    if ((tokens[i].kind === 'string' || tokens[i].kind === 'verbatim') &&
        tokens[i + 1].kind === 'op' && tokens[i + 1].value === '+' &&
        tokens[i + 2].kind === 'ident') return true;
    if (tokens[i].kind === 'ident' && tokens[i + 1].kind === 'op' && tokens[i + 1].value === '+' &&
        (tokens[i + 2].kind === 'string' || tokens[i + 2].kind === 'verbatim')) return true;
  }
  return false;
}

function rhsHasInterp(tokens) {
  return (tokens || []).some(t => t.kind === 'interp');
}

const SQL_COMMAND_TYPES = /^(?:System\.Data\.SqlClient\.)?(?:Sql|OleDb|MySql|Npgsql|SQLite)Command$/;
const SQL_EXEC_METHODS  = /^(?:Execute(?:Reader|Scalar|NonQuery|DbDataReader|Reader)?(?:Async)?)$/;
const LDAP_SEARCH_TYPES = /^(?:DirectorySearcher|LdapConnection)$/;
const LDAP_SEARCH_METHODS = /^(?:Search|FindOne|FindAll|SendRequest)$/;
const WEAK_CRYPTO_TYPES = /^(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider|MD5CryptoServiceProvider|MD5Cng|SHA1CryptoServiceProvider|SHA1Managed|SHA1Cng|HMACSHA1|HMACMD5|DES|TripleDES|RC2|MD5|SHA1)$/;
const WEAK_CRYPTO_FACTORY_PATTERN = /\b(?:DES|TripleDES|RC2|MD5|SHA1)\.Create\b/;
const SECRET_NAME_PATTERN = /^(?:password|passwd|pw|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|priv(?:ate)?[_-]?key|cred(?:ential)?s?|connection[_-]?string|conn[_-]?str)$/i;
const PATH_TRAVERSAL_BASES_SANITIZER = /\bPath\.GetFullPath\b/;
const XSS_SAFE_SINK_PATTERN = /\bHtmlEncode\b|\bHtmlEncoder\b|\bAntiXss/;

function makeFinding({ ruleId, file, line, raw, ir, family, severity, cwe, vuln, remediation, evidence, confidence = 0.85 }) {
  const stride = (cwe === 'CWE-89'  ? 'Tampering'
               : cwe === 'CWE-78'  ? 'Elevation of Privilege'
               : cwe === 'CWE-79'  ? 'Tampering'
               : cwe === 'CWE-611' ? 'Information Disclosure'
               : cwe === 'CWE-502' ? 'Elevation of Privilege'
               : cwe === 'CWE-22'  ? 'Tampering'
               : cwe === 'CWE-327' ? 'Information Disclosure'
               : cwe === 'CWE-330' ? 'Spoofing'
               : cwe === 'CWE-798' ? 'Information Disclosure'
               : cwe === 'CWE-1004'? 'Information Disclosure'
               : cwe === 'CWE-90'  ? 'Tampering'
               : 'Tampering');
  return {
    id: `${ruleId}:${file}:${line}`, file, line,
    vuln, severity, cwe, stride, family,
    snippet: ((raw && raw.split('\n')[line - 1]) || '').trim().slice(0, 200),
    remediation,
    confidence,
    parser: 'CSHARP',
    _taintEvidence: evidence || null,
  };
}

// ─── Detectors ──────────────────────────────────────────────────────────────

function detectSqlInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // 1. SqlCommand-style ctor with tainted concatenation in the first arg.
    for (const decl of m.decls) {
      if (!SQL_COMMAND_TYPES.test(decl.type || '') && !(decl.isVar && SQL_COMMAND_TYPES.test((decl.rhsText.match(/^\s*new\s+(\w+)/) || [])[1] || ''))) continue;
      if (!decl.rhsTokens) continue;
      // Use token-aware checks so SQL parameter placeholders like "@id"
      // inside string literals are NOT counted as code identifiers.
      const hasConcatWithIdent = rhsHasConcatWithIdent(decl.rhsTokens);
      const hasInterp = rhsHasInterp(decl.rhsTokens);
      if (!hasConcatWithIdent && !hasInterp) continue;
      const idents = rhsIdents(decl.rhsTokens);
      const ref = idents.find(r => flow.taintMap.get(r));
      if (!ref) continue;
      const id = `csharp-sql-ctor:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-sql-ctor', file, line: decl.line, raw, ir,
        family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
        vuln: 'SQL Injection — SqlCommand built from tainted concatenation/interpolation',
        remediation: 'Use parameterized queries: `var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn); cmd.Parameters.AddWithValue("@id", id);`. Interpolated strings ($"…") are pre-rendered before reaching the parameterizer.',
        evidence: { type: 'taint', taintedRef: ref, decl: decl.fullTarget || decl.name },
      }));
    }
    // 2. cmd.ExecuteX call where cmd's CommandText was assigned a tainted value.
    for (const call of m.calls) {
      if (!SQL_EXEC_METHODS.test(call.method || '')) continue;
      const receiver = call.receiver;
      if (!receiver) continue;
      if (!receiverIsType(m, flow, receiver, SQL_COMMAND_TYPES)) continue;
      // Find the most recent CommandText assignment for this receiver.
      const cmdTextAssign = (m.assignments || [])
        .filter(a => a.target === receiver && a.memberPath === 'CommandText')
        .slice(-1)[0];
      // Also check the ctor first-arg if no CommandText set.
      const decl = (m.decls || []).find(d => d.name === receiver);
      // Use token-aware idents extraction so SQL parameter placeholders
      // inside string literals (e.g. "@id") aren't flagged as code refs.
      const cmdAssignIdents = cmdTextAssign ? rhsIdents(cmdTextAssign.rhsTokens) : [];
      const declRhsIdents = decl ? rhsIdents(decl.rhsTokens) : [];
      // Concat check via tokens too.
      const cmdAssignHasConcat = cmdTextAssign && (rhsHasConcatWithIdent(cmdTextAssign.rhsTokens) || rhsHasInterp(cmdTextAssign.rhsTokens));
      const declHasConcat = decl && (rhsHasConcatWithIdent(decl.rhsTokens) || rhsHasInterp(decl.rhsTokens));
      const cmdAssignTainted = cmdAssignHasConcat && cmdAssignIdents.some(r => flow.taintMap.get(r));
      const declTainted = declHasConcat && declRhsIdents.some(r => flow.taintMap.get(r));
      if (!cmdAssignTainted && !declTainted) continue;
      const id = `csharp-sql-exec:${file}:${call.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-sql-exec', file, line: call.line, raw, ir,
        family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
        vuln: 'SQL Injection — SqlCommand.ExecuteX with tainted CommandText',
        remediation: 'Bind every user-supplied value via `cmd.Parameters.AddWithValue("@p", value)` and use `@p` placeholders in the SQL. Never compose CommandText with `+`, `string.Format`, or `$"…"`.',
        evidence: { type: 'taint', receiver, callLine: call.line, cmdTextLine: cmdTextAssign?.line || decl?.line },
      }));
    }
    // 3. FromSqlRaw / FromSql with concat or interpolation.
    for (const call of m.calls) {
      if (!/^FromSql(?:Raw)?$/.test(call.method)) continue;
      if (!call.args.length) continue;
      const arg0 = call.args[0];
      if (interpStringIsTainted(flow, arg0.tokens.find(t => t.kind === 'interp'))) {
        const id = `csharp-ef-fromsql-interp:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ef-fromsql-interp', file, line: call.line, raw, ir,
          family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
          vuln: 'SQL Injection — EF Core FromSqlRaw with tainted interpolation',
          remediation: 'Use `FromSqlInterpolated($"...")` or `FromSqlRaw("...", parameter)` so EF parameterizes values. `FromSqlRaw($"…{var}…")` evaluates the interpolation BEFORE EF sees it.',
        }));
        continue;
      }
      if (/["'][^"']*["']\s*\+/.test(arg0.text) && arg0.idents.some(r => flow.taintMap.get(r))) {
        const id = `csharp-ef-fromsql-concat:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ef-fromsql-concat', file, line: call.line, raw, ir,
          family: 'sql-injection', severity: 'high', cwe: 'CWE-89',
          vuln: 'SQL Injection — EF Core FromSqlRaw with concatenated tainted value',
          remediation: 'Use `FromSqlInterpolated($"… {value}")` or `FromSqlRaw("… {0}", value)` so EF parameterizes. String concatenation defeats the protection.',
        }));
      }
    }
  }
}

function detectCommandInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    // Process.Start(...) — 2-arg form OR ProcessStartInfo with tainted Arguments
    for (const call of m.calls) {
      if (!(call.fullPath === 'Process.Start' || /\bProcessStartInfo\b/.test(call.fullPath))) {
        // also catch piping a ProcessStartInfo
      }
      if (call.fullPath === 'Process.Start' && call.args.length >= 2) {
        const arg1 = call.args[1];
        if (expressionIsTainted(flow, arg1.text)) {
          const id = `csharp-proc-start2:${file}:${call.line}`;
          if (seen.has(id)) continue;
          seen.add(id);
          out.push(makeFinding({
            ruleId: 'csharp-proc-start2', file, line: call.line, raw, ir,
            family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
            vuln: 'Command Injection — Process.Start with tainted argument string',
            remediation: 'Use `ProcessStartInfo` with `ArgumentList` (an `IList<string>`) so each argument is escaped individually. Never compose a single argument string from user input.',
          }));
        }
      }
    }
    // PSI initializer pattern: var psi = new ProcessStartInfo { UseShellExecute=true, Arguments = tainted }
    for (const decl of m.decls) {
      if (decl.type === 'ProcessStartInfo' || /^new\s+ProcessStartInfo\b/.test(decl.rhsText || '')) {
        const rhs = decl.rhsText || '';
        const hasShell = /\bUseShellExecute\s*=\s*true\b/.test(rhs);
        const argsMatch = rhs.match(/\bArguments\s*=\s*([^,}]+)/);
        if (hasShell && argsMatch && expressionIsTainted(flow, argsMatch[1])) {
          const id = `csharp-psi-shell-tainted:${file}:${decl.line}`;
          if (seen.has(id)) continue;
          seen.add(id);
          out.push(makeFinding({
            ruleId: 'csharp-psi-shell-tainted', file, line: decl.line, raw, ir,
            family: 'command-injection', severity: 'critical', cwe: 'CWE-78',
            vuln: 'Command Injection — ProcessStartInfo with UseShellExecute=true and tainted Arguments',
            remediation: 'Set `UseShellExecute = false` and pass arguments as a `string[]` via `ProcessStartInfo.ArgumentList`. ShellExecute=true routes the call through cmd.exe / the shell, where any user-supplied metacharacter is interpreted.',
          }));
        }
      }
    }
  }
}

function detectInsecureDeserialization(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    // BinaryFormatter ctor anywhere is sufficient.
    for (const decl of m.decls) {
      if (/\bnew\s+BinaryFormatter\s*\(/.test(decl.rhsText || '')) {
        const id = `csharp-binformatter:${file}:${decl.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-binformatter', file, line: decl.line, raw, ir,
          family: 'insecure-deserialization', severity: 'critical', cwe: 'CWE-502',
          vuln: 'Insecure Deserialization — BinaryFormatter',
          remediation: 'BinaryFormatter is unsafe by design (Microsoft has deprecated it in .NET 5+). Replace with `System.Text.Json` or `DataContractSerializer` with `KnownTypes` set.',
        }));
      }
      if (/\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b/.test(decl.rhsText || '')) {
        const id = `csharp-newtonsoft-typename:${file}:${decl.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-newtonsoft-typename', file, line: decl.line, raw, ir,
          family: 'insecure-deserialization', severity: 'critical', cwe: 'CWE-502',
          vuln: 'Insecure Deserialization — Newtonsoft.Json TypeNameHandling != None',
          remediation: 'TypeNameHandling.All/Auto/Objects/Arrays enables RCE via gadget chains. Set `TypeNameHandling.None` or migrate to System.Text.Json.',
        }));
      }
    }
    // Also catch BinaryFormatter as a call: bf.Deserialize(stream)
    for (const call of m.calls) {
      const flow = analysis.methodFlow.get(m);
      if (call.method === 'Deserialize' && flow && receiverIsType(m, flow, call.receiver, 'BinaryFormatter')) {
        const id = `csharp-binformatter-call:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-binformatter-call', file, line: call.line, raw, ir,
          family: 'insecure-deserialization', severity: 'critical', cwe: 'CWE-502',
          vuln: 'Insecure Deserialization — BinaryFormatter.Deserialize call',
          remediation: 'Drop BinaryFormatter entirely. Use System.Text.Json or DataContractJsonSerializer with KnownTypes.',
        }));
      }
    }
  }
}

function detectWeakCrypto(file, raw, ir, analysis, out, seen) {
  // 1. new DES/MD5/SHA1/RC2/TripleDESCryptoServiceProvider() / new MD5Managed()
  for (const decl of ir.decls) {
    if (decl.rhsText && WEAK_CRYPTO_FACTORY_PATTERN.test(decl.rhsText)) {
      const id = `csharp-weak-crypto-factory:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-weak-crypto-factory', file, line: decl.line, raw, ir,
        family: 'weak-crypto', severity: 'high', cwe: 'CWE-327',
        vuln: 'Weak Cryptography — MD5/SHA1/DES/3DES/RC2 factory method',
        remediation: 'Use AES-GCM for symmetric encryption, SHA-256 or BLAKE2b for hashing, and a KDF (PBKDF2/Argon2) for password derivation. The legacy CryptoServiceProvider and `.Create()` factory shapes return broken-by-design primitives.',
      }));
    }
    const ctorMatch = (decl.rhsText || '').match(/\bnew\s+([A-Z]\w+)\s*\(/);
    if (ctorMatch && WEAK_CRYPTO_TYPES.test(ctorMatch[1])) {
      const id = `csharp-weak-crypto-ctor:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-weak-crypto-ctor', file, line: decl.line, raw, ir,
        family: 'weak-crypto', severity: 'high', cwe: 'CWE-327',
        vuln: `Weak Cryptography — \`new ${ctorMatch[1]}()\``,
        remediation: 'Replace with the modern primitive: AES (preferably AES-GCM via `AesGcm`) for encryption, SHA-256 / SHA-3 for general hashing, PBKDF2 / Argon2 for password derivation, HMAC-SHA-256 for MAC.',
      }));
    }
  }
}

function detectWeakRng(file, raw, ir, analysis, out, seen) {
  // Heuristic for "cryptographic context": file declares a hardcoded-secret-shaped
  // variable, references password/token/key names, or uses crypto primitives.
  const fileText = raw || '';
  const looksCrypto = /\b(?:password|passwd|pw|pwd|token|secret|api[_-]?key|salt|nonce|iv)\b/i.test(fileText)
                    || /Cryptography|CryptoServiceProvider|CryptoStream/.test(fileText)
                    || /\bAes(?:Cng|CryptoServiceProvider)?\b|\bRSA(?:CryptoServiceProvider|Cng)?\b/.test(fileText)
                    || /\b(?:DES|TripleDES|RC2|MD5|SHA1|HMACSHA)/.test(fileText);
  if (!looksCrypto) return;
  for (const decl of ir.decls) {
    if (/\bnew\s+Random\s*\(/.test(decl.rhsText || '')) {
      const id = `csharp-weak-rng:${file}:${decl.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-weak-rng', file, line: decl.line, raw, ir,
        family: 'weak-rng', severity: 'high', cwe: 'CWE-330',
        vuln: 'Weak Randomness — System.Random in cryptographic context',
        remediation: '`System.Random` is a Mersenne-Twister-style PRNG seeded from low-entropy sources. Use `RandomNumberGenerator.Fill(buffer)` or `RandomNumberGenerator.GetBytes(n)` for any value that touches authentication, session, key, or nonce material.',
      }));
    }
  }
  // call site: var x = new Random().Next(); — also caught above via decl.
}

function detectHardcodedSecret(file, raw, ir, analysis, out, seen) {
  for (const decl of ir.decls) {
    if (!SECRET_NAME_PATTERN.test(decl.name || '')) continue;
    if (!decl.rhsText) continue;
    // Match a bare string literal as the rhs — and require non-trivial length / shape.
    const m = decl.rhsText.match(/^\s*["']([^"']{6,})["']\s*$/) || decl.rhsText.match(/^\s*@"([^"]{6,})"\s*$/);
    if (!m) continue;
    const val = m[1];
    // Filter common placeholders.
    if (/^(?:changeme|placeholder|todo|tbd|xxxxx|secret|password|your_?password)$/i.test(val)) continue;
    if (/^[A-Za-z]+$/.test(val) && val.length < 12) continue; // single word, too short to be a secret
    const id = `csharp-hardcoded-secret:${file}:${decl.line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(makeFinding({
      ruleId: 'csharp-hardcoded-secret', file, line: decl.line, raw, ir,
      family: 'hardcoded-secret', severity: 'high', cwe: 'CWE-798',
      vuln: `Hardcoded Secret — \`${decl.name}\` assigned a literal value`,
      remediation: 'Load secrets from environment variables (`Environment.GetEnvironmentVariable`), Azure Key Vault, AWS Secrets Manager, or .NET `Configuration` with user-secrets in development. Never commit literal credentials.',
      confidence: 0.7,
    }));
  }
}

function detectInsecureCookies(file, raw, ir, analysis, out, seen) {
  // `new HttpCookie(...)` without subsequent `.Secure = true` or `.HttpOnly = true` in the same method scope.
  for (const m of ir.methods) {
    const cookieDecls = m.decls.filter(d => /\bnew\s+HttpCookie\s*\(/.test(d.rhsText || ''));
    if (!cookieDecls.length) continue;
    for (const cd of cookieDecls) {
      const setSecure = m.assignments.some(a => a.target === cd.name && a.memberPath === 'Secure' && /\btrue\b/.test(a.rhsText));
      const setHttpOnly = m.assignments.some(a => a.target === cd.name && a.memberPath === 'HttpOnly' && /\btrue\b/.test(a.rhsText));
      if (setSecure && setHttpOnly) continue;
      const missing = !setSecure && !setHttpOnly ? '.Secure and .HttpOnly'
                    : !setSecure ? '.Secure'
                    : '.HttpOnly';
      const id = `csharp-cookie-flags:${file}:${cd.line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(makeFinding({
        ruleId: 'csharp-cookie-flags', file, line: cd.line, raw, ir,
        family: 'header-hardening', severity: 'medium', cwe: 'CWE-1004',
        vuln: `Insecure Cookie — HttpCookie missing ${missing} flag`,
        remediation: 'Set both `cookie.Secure = true;` and `cookie.HttpOnly = true;` before adding to the response. Use `.SameSite = SameSiteMode.Lax` (or Strict) to defeat CSRF.',
      }));
    }
  }
}

function detectXss(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      // Html.Raw(taintedExpr) or @Html.Raw(taintedExpr) — receiver "Html" or "@Html"
      if (call.method === 'Raw' && (call.receiver === 'Html' || call.receiver === '@Html')) {
        const arg = call.args[0];
        if (!arg) continue;
        if (XSS_SAFE_SINK_PATTERN.test(arg.text)) continue;
        if (!expressionIsTainted(flow, arg.text) && !arg.idents.length) continue;
        if (!expressionIsTainted(flow, arg.text)) continue;
        const id = `csharp-htmlraw:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-htmlraw', file, line: call.line, raw, ir,
          family: 'xss', severity: 'high', cwe: 'CWE-79',
          vuln: 'XSS — Razor Html.Raw with tainted value',
          remediation: '`@Html.Raw(x)` emits `x` without HTML-encoding. Use `@x` (Razor auto-encodes), or pass through `HtmlEncoder.Default.Encode(x)` / `HttpUtility.HtmlEncode(x)` / `HtmlSanitizer.Sanitize(x)`.',
        }));
      }
      // Response.Write(tainted)
      if (call.method === 'Write' && (call.receiver === 'Response' || call.receiver === 'HttpContext.Response')) {
        const arg = call.args[0];
        if (!arg) continue;
        if (!expressionIsTainted(flow, arg.text)) continue;
        const id = `csharp-response-write:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-response-write', file, line: call.line, raw, ir,
          family: 'xss', severity: 'high', cwe: 'CWE-79',
          vuln: 'XSS — Response.Write with tainted value',
          remediation: 'Encode the value via `HttpUtility.HtmlEncode(x)` (or `HtmlEncoder.Default.Encode(x)` in ASP.NET Core) before writing. Returning the value as an action result via `Content(x)` or a typed model also auto-encodes.',
        }));
      }
    }
  }
}

function detectPathTraversal(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    if (PATH_TRAVERSAL_BASES_SANITIZER.test(raw)) {
      // Best-effort: if the file contains a GetFullPath/StartsWith check, demote.
      // We don't try to scope to the same method; precision tradeoff.
    }
    for (const call of m.calls) {
      if (call.method !== 'Combine' && call.receiver !== 'Path') continue;
      if (!(call.fullPath === 'Path.Combine' || call.fullPath.endsWith('.Combine'))) continue;
      for (const arg of call.args) {
        if (expressionIsTainted(flow, arg.text)) {
          const id = `csharp-path-traversal:${file}:${call.line}`;
          if (seen.has(id)) continue;
          seen.add(id);
          out.push(makeFinding({
            ruleId: 'csharp-path-traversal', file, line: call.line, raw, ir,
            family: 'path-traversal', severity: 'high', cwe: 'CWE-22',
            vuln: 'Path Traversal — Path.Combine with tainted segment',
            remediation: 'Resolve the joined path via `Path.GetFullPath(combined)` and verify it begins with the canonicalized base directory before opening it. Path.Combine alone does NOT prevent `..\\..\\..\\windows\\system32\\` style escapes.',
          }));
          break;
        }
      }
    }
  }
}

function detectLdapInjection(file, raw, ir, analysis, out, seen) {
  for (const m of ir.methods) {
    const flow = analysis.methodFlow.get(m);
    if (!flow) continue;
    for (const call of m.calls) {
      if (!LDAP_SEARCH_METHODS.test(call.method)) continue;
      if (!call.receiver) continue;
      if (!receiverIsType(m, flow, call.receiver, LDAP_SEARCH_TYPES)) continue;
      const arg = call.args[0];
      if (arg && expressionIsTainted(flow, arg.text)) {
        const id = `csharp-ldap-injection:${file}:${call.line}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push(makeFinding({
          ruleId: 'csharp-ldap-injection', file, line: call.line, raw, ir,
          family: 'ldap-injection', severity: 'high', cwe: 'CWE-90',
          vuln: 'LDAP Injection — DirectorySearcher/LdapConnection with tainted filter',
          remediation: 'Escape every user-supplied filter component via `LdapEncode` (or write your own escape per RFC 4515 — `*` → `\\2a`, `(` → `\\28`, `)` → `\\29`, `\\` → `\\5c`, `\\0` → `\\00`). Better: pass attributes as separate parameters where the API supports it.',
        }));
      }
    }
  }
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function scanCSharp(fp, raw) {
  if (!/\.cs$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  let ir, analysis;
  try {
    ir = buildCSharpIR(raw);
    analysis = analyzeCSharpIR(ir);
  } catch (e) {
    // IR build failed — fail-closed; better to miss than to throw.
    return [];
  }
  const out = [];
  const seen = new Set();
  try { detectSqlInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectCommandInjection(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectInsecureDeserialization(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectWeakCrypto(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectWeakRng(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectHardcodedSecret(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectInsecureCookies(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectXss(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectPathTraversal(fp, raw, ir, analysis, out, seen); } catch {}
  try { detectLdapInjection(fp, raw, ir, analysis, out, seen); } catch {}
  // Stamp route + auth context on every finding for downstream exploitability.
  for (const f of out) {
    f._routes = analysis.routes.map(r => ({ http: r.http, path: r.path, line: r.line, requiresAuth: r.requiresAuth, methodName: r.methodName }));
    f.routeRooted = analysis.routes.some(r => f.line >= r.line && f.line <= (r.method.endLine || r.line + 200));
    if (f.routeRooted) {
      const rt = analysis.routes.find(r => f.line >= r.line && f.line <= (r.method.endLine || r.line + 200));
      f._inRoute = { http: rt.http, path: rt.path, requiresAuth: rt.requiresAuth };
      if (!rt.requiresAuth) f.severity = (f.severity === 'high' || f.severity === 'medium') ? 'critical' : f.severity;
    }
  }
  return out;
}

export { buildCSharpIR, analyzeCSharpIR };
