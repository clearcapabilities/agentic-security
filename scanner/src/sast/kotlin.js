import { blankComments } from './_comment-strip.js';
// Kotlin-specific patterns. Most JVM-class vulns are caught by the existing
// java-* modules (which match on `.java|.kt` extension wherever practical).
// This module adds detectors for Kotlin-only idioms that those rules miss:
//
//   - !! force unwrap on user input (NPE → DoS)
//   - runBlocking { ... } on what looks like the main thread (blocks event loop)
//   - val/var that captures req.* into a public top-level (exposes user data)
//   - Runtime.exec / ProcessBuilder fed by !! or by request properties
//   - YAML.load (snakeyaml) without SafeConstructor
//   - Unsafe Gson fromJson on a polymorphic type
//   - File.readText(req.input) — direct user-controlled file read

const RE = {
  forceUnwrap: /\b(?:request|req|input|userInput|params)\b[^=\n]{0,80}!!/g,
  runBlockingTop: /^[\t ]*runBlocking\s*\{/gm,
  unsafeYaml: /\bYaml\s*\(\s*\)\s*\.\s*load\b|\bYaml\s*\(\s*\)\s*\.\s*loadAll\b/g,
  exec: /\bRuntime\.getRuntime\(\)\s*\.\s*exec\s*\(\s*[^)]*\b(?:request|req|input|params|userInput)\b/g,
  gsonPolymorphic: /\bGson\(\)\s*\.\s*fromJson\s*\(\s*[^,)]+,\s*(?:Any::class|Object::class)/g,
  fileReadText: /\bFile\s*\(\s*[^)]*\b(?:request|req|input|userInput|params)\b[^)]*\)\s*\.\s*read(?:Text|Bytes|Lines)/g,
  // Structural (taint-independent) detectors: a dangerous sink built with a
  // Kotlin string template (`${x}` / `$x`) or string concatenation (`"…" +`)
  // is the injection shape regardless of the variable's name — parameterized
  // queries / array-form exec / canonicalized paths never interpolate. A pure
  // string literal (no template, no concat) does NOT match, so this stays
  // high-precision and complements the taint engine (which needs a source).
  sqlInjection: /\b(?:executeQuery|executeUpdate|prepareStatement|prepareCall|createQuery|createNativeQuery|nativeQuery|rawQuery)\s*\(\s*"[^"\n]*(?:\$\{?[A-Za-z_]|"\s*\+)/g,
  cmdInjectionStructural: /\b(?:Runtime\.getRuntime\(\)\s*\.\s*exec|ProcessBuilder)\s*\(\s*(?:listOf\s*\(\s*)?"[^"\n]*(?:\$\{?[A-Za-z_]|"\s*\+)/g,
  pathTraversalStructural: /\b(?:File|FileInputStream|FileReader|FileOutputStream|RandomAccessFile|Paths\.get)\s*\(\s*"[^"\n]*(?:\$\{?[A-Za-z_]|"\s*\+)/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanKotlin(fp, raw) {
  if (!/\.kt(?:s)?$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      const meta = {
        forceUnwrap: {
          vuln: 'Kotlin force-unwrap (!!) on user input — null causes runtime crash (DoS)',
          severity: 'medium', cwe: 'CWE-476',
          remediation: 'Replace `!!` with `?:` (elvis) returning a safe default, or `?.let { ... }` to skip when null. Force-unwrap on attacker-controllable input lets the client throw 500s at will.',
        },
        runBlockingTop: {
          vuln: 'runBlocking { ... } at top-level — blocks the calling thread, often the event loop in Ktor/Spring WebFlux',
          severity: 'low', cwe: 'CWE-400',
          remediation: 'Replace with a `CoroutineScope(Dispatchers.IO).launch { ... }` or use the framework\'s suspend-aware handler. `runBlocking` in a non-test context kills throughput under load.',
        },
        unsafeYaml: {
          vuln: 'Unsafe YAML.load() — SnakeYAML default constructor instantiates arbitrary classes',
          severity: 'high', cwe: 'CWE-502',
          remediation: 'Use `Yaml(SafeConstructor())` or a typed config library (Hoplite, kotlinx-serialization-yaml). Default `Yaml().load()` lets a crafted YAML file instantiate arbitrary classes — same risk class as Java deserialization.',
        },
        exec: {
          vuln: 'Command Injection — Runtime.exec with user-controlled input (Kotlin)',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `ProcessBuilder(listOf("cmd", arg1, arg2))` with an array form so the shell never parses anything. Never pass `Runtime.getRuntime().exec("cmd " + input)`.',
        },
        gsonPolymorphic: {
          vuln: 'Gson polymorphic deserialization (Any::class / Object::class) — gadget chain risk',
          severity: 'high', cwe: 'CWE-502',
          remediation: 'Define a concrete target class. Gson `fromJson(json, Any::class)` lets the JSON dictate the target type — a vector for known gadget chains in the classpath.',
        },
        fileReadText: {
          vuln: 'Path Traversal: File.readText with user-controlled path (Kotlin)',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize and verify the path is within an allowed base directory before reading: `if (!File(path).canonicalPath.startsWith(baseDir.canonicalPath)) throw ...`. Better: store files by content-hash filenames generated server-side and let the client request by hash, never by user-supplied path.',
        },
        sqlInjection: {
          vuln: 'SQL Injection — query built with a Kotlin string template / concat (Kotlin)',
          severity: 'critical', cwe: 'CWE-89',
          remediation: 'Use a parameterized query: `prepareStatement("… WHERE name = ?")` then `setString(1, name)`. Never interpolate (`${…}`) or concatenate untrusted values into SQL.',
        },
        cmdInjectionStructural: {
          vuln: 'Command Injection — exec built with a string template / concat (Kotlin)',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `ProcessBuilder(listOf("cmd", arg1, arg2))` (array form) so no shell parses the string. Never concatenate or interpolate input into a command string.',
        },
        pathTraversalStructural: {
          vuln: 'Path Traversal — file path built with a string template / concat (Kotlin)',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize and assert the path stays within an allow-listed base dir before opening: `require(File(base, name).canonicalPath.startsWith(File(base).canonicalPath))`. Do not interpolate untrusted segments into a path.',
        },
      }[key];
      push({
        id: `kotlin-${key}:${fp}:${line}`,
        file: fp, line,
        vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: meta.remediation,
        parser: 'KOTLIN',
        confidence: 0.75,
      });
    }
  }
  // XXE (CWE-611): an XML factory that parses without DTD/external-entity
  // hardening. Flag only when no secure-processing config is present anywhere
  // in the file (so the fixed form with setFeature(...) is not flagged).
  const XXE_FACTORY = /\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|XMLReaderFactory|TransformerFactory)\b/;
  const XXE_PARSE = /\.(?:parse|newDocumentBuilder|newSAXParser|createXMLStreamReader|read)\s*\(/;
  const XXE_GUARD = /setFeature|disallow-doctype-decl|external-general-entities|external-parameter-entities|FEATURE_SECURE_PROCESSING|setExpandEntityReferences\s*\(\s*false|ACCESS_EXTERNAL_DTD|XMLConstants/i;
  if (XXE_FACTORY.test(code) && XXE_PARSE.test(code) && !XXE_GUARD.test(code)) {
    const idx = code.search(XXE_FACTORY);
    const line = lineOf(code, idx);
    push({
      id: `kotlin-xxe:${fp}:${line}`, file: fp, line,
      vuln: 'XXE — XML parser without DTD/external-entity hardening (Kotlin)',
      severity: 'high', cwe: 'CWE-611',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Disable DTDs/external entities: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and external-general-entities=false, or set XMLConstants.FEATURE_SECURE_PROCESSING.',
      parser: 'KOTLIN', confidence: 0.6,
    });
  }
  // SSRF (CWE-918): URL/URI opened from a non-literal or templated value,
  // unless a host-validation guard (allow/deny-list, RFC1918/metadata check)
  // is present in the file — the fixed form keeps URL(var) but adds the check.
  const SSRF_SINK = /\b(?:URL|URI|HttpURLConnection)\s*\(\s*(?:"[^"\n]*\$\{?[A-Za-z_]|[A-Za-z_]\w*\s*\))/;
  const SSRF_GUARD = /\.host\b[^\n]*\b(?:in|!in)\b|allow(?:ed)?Hosts?|isLoopback|isSiteLocal|isLinkLocal|169\.254\.169\.254|require\s*\([^)]*\bhost\b|InetAddress|block(?:list|ed)|denylist/i;
  if (SSRF_SINK.test(code) && !SSRF_GUARD.test(code)) {
    const idx = code.search(SSRF_SINK);
    const line = lineOf(code, idx);
    push({
      id: `kotlin-ssrf:${fp}:${line}`, file: fp, line,
      vuln: 'SSRF — URL/URI opened from a non-literal or templated value (Kotlin)',
      severity: 'high', cwe: 'CWE-918',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Resolve the host and reject RFC1918 / link-local / metadata (169.254.169.254) addresses before opening the connection, or restrict to an allow-list of hosts.',
      parser: 'KOTLIN', confidence: 0.55,
    });
  }
  // Insecure deserialization (CWE-502): native ObjectInputStream.readObject.
  if (/\bObjectInputStream\s*\(/.test(code) && /\.\s*readObject\s*\(/.test(code)) {
    const idx = code.search(/\bObjectInputStream\s*\(/);
    const line = lineOf(code, idx);
    push({
      id: `kotlin-deser:${fp}:${line}`, file: fp, line,
      vuln: 'Insecure Deserialization — ObjectInputStream.readObject on untrusted data (Kotlin)',
      severity: 'high', cwe: 'CWE-502',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Never deserialize untrusted data with native Java/Kotlin serialization. Use a typed format (kotlinx.serialization, Jackson with a fixed type, protobuf); if unavoidable, install a strict ObjectInputFilter allow-list.',
      parser: 'KOTLIN', confidence: 0.6,
    });
  }
  return findings;
}
