// Client-side / React security audit.
//
// The main SAST engine focuses on server-side patterns. This module covers
// browser-side attack surface: unsafe HTML injection, auth tokens in Web
// Storage, open redirects in client routing, and unsafe postMessage handling.
//
// F1 safety:
//   - Only scans JSX/TSX files and JS files with recognisable React/component patterns
//   - Uses multi-signal patterns to minimise FP rate
//   - NONPROD_RE excludes test fixtures
//   - Benchmark apps (NodeGoat = server-rendered, Juice Shop = Angular, OWASP = Java)
//     do not use React patterns targeted here → no benchmark FP risk

const _JSX_EXT_RE = /\.(?:jsx|tsx)$/i;
const _JS_EXT_RE = /\.(?:js|mjs|ts)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|stories|node_modules)\//i;

// React component signal for plain JS/TS files (to avoid scanning backend Node files)
const REACT_SIGNAL_RE = /(?:import\s+React|from\s+['"]react['"]|useState|useEffect|JSX\.Element|ReactNode|React\.FC)/;

// --- dangerouslySetInnerHTML ---
// Fire when the innerHTML expression is NOT already wrapped in a known sanitizer.
const DANGEROUS_HTML_RE = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g;
const SANITIZER_RE = /DOMPurify\.sanitize|sanitize\s*\(|xss\s*\(|purify\s*\(|bleach\.clean|sanitizeHtml\s*\(/i;

// --- localStorage / sessionStorage with auth-sensitive keys ---
const LOCAL_STORAGE_SET_RE = /(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"`][^'"`]*(?:token|auth|session|jwt|key|credential|secret|access|refresh|id_token|bearer)[^'"`]*['"`]/i;

// --- window.location / router.push with user input ---
const CLIENT_REDIRECT_RE = /(?:window\.location(?:\.href)?\s*=|router\.push\s*\(|navigate\s*\()\s*(?:(?:req|props|params|query|searchParams|location|history)\.|`[^`]*\$\{)/;

// --- postMessage without origin check ---
// Fires when addEventListener('message', ...) exists without event.origin check nearby
const POST_MESSAGE_LISTENER_RE = /addEventListener\s*\(\s*['"`]message['"`]/;
const ORIGIN_CHECK_RE = /event\.origin\b|e\.origin\b|msg\.origin\b|\.origin\s*[!=]{2,3}|\.origin\.includes|trustedOrigins/;

// --- eval / Function constructor with dynamic input in component context ---
const CLIENT_EVAL_RE = /\beval\s*\((?!(?:\s*['"`][^'"`]+['"`]\s*\)))/;
const FUNCTION_CONSTRUCTOR_RE = /new\s+Function\s*\([^)]*(?:props|state|params|query|input|user|data)\b/;

function _lineOf(content, matchIndex) {
  return content.slice(0, matchIndex).split('\n').length;
}

function scanClientSide(file, content) {
  if (_NONPROD_RE.test(file)) return [];
  const isJsx = _JSX_EXT_RE.test(file);
  const isJs = _JS_EXT_RE.test(file);
  if (!isJsx && !isJs) return [];
  // For plain JS/TS files, require React signal to avoid firing on server code
  if (isJs && !REACT_SIGNAL_RE.test(content)) return [];

  const findings = [];
  const lines = content.split('\n');

  // dangerouslySetInnerHTML
  {
    let m;
    const re = new RegExp(DANGEROUS_HTML_RE.source, 'g');
    while ((m = re.exec(content)) !== null) {
      // Check surrounding context (~300 chars) for a sanitizer call
      const ctx = content.slice(Math.max(0, m.index - 200), m.index + 200);
      if (!SANITIZER_RE.test(ctx)) {
        findings.push({
          id: `client-side:DANGEROUS_INNERHTML:${file}:${_lineOf(content, m.index)}`,
          title: 'dangerouslySetInnerHTML without sanitizer — XSS risk',
          severity: 'high',
          file, line: _lineOf(content, m.index),
          vuln: 'React — dangerouslySetInnerHTML without Sanitizer',
          description: 'dangerouslySetInnerHTML injects raw HTML into the DOM. If the content includes any user-controlled data, attackers can inject `<script>` tags or event handlers and execute arbitrary JavaScript in the user\'s browser, stealing session cookies or performing actions as the victim.',
          remediation: 'Sanitize HTML before injecting:\n  import DOMPurify from "dompurify";\n  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }}\nBetter: use a markdown renderer or a component library that escapes HTML by default.',
          cwe: 'CWE-79',
        });
      }
    }
  }

  // localStorage/sessionStorage with auth-sensitive key
  for (let i = 0; i < lines.length; i++) {
    if (LOCAL_STORAGE_SET_RE.test(lines[i])) {
      const storage = /sessionStorage/.test(lines[i]) ? 'sessionStorage' : 'localStorage';
      findings.push({
        id: `client-side:TOKEN_IN_WEBSTORAGE:${file}:${i + 1}`,
        title: `Auth token stored in ${storage} — XSS-accessible credential`,
        severity: 'medium',
        file, line: i + 1,
        vuln: 'Client-Side — Auth Token in Web Storage',
        description: `Auth tokens stored in ${storage} are accessible to any JavaScript running on the page. An XSS vulnerability anywhere on the domain — including in a third-party script — lets an attacker steal the token and impersonate the user indefinitely.`,
        remediation: 'Store auth tokens in httpOnly, Secure, SameSite=Lax cookies instead of Web Storage. httpOnly cookies are inaccessible to JavaScript even under XSS. If you use NextAuth or Clerk, they handle this correctly by default — ensure you haven\'t overridden the storage mechanism.',
        cwe: 'CWE-922',
      });
    }
  }

  // Client-side open redirect with dynamic input
  for (let i = 0; i < lines.length; i++) {
    if (CLIENT_REDIRECT_RE.test(lines[i])) {
      findings.push({
        id: `client-side:OPEN_REDIRECT:${file}:${i + 1}`,
        title: 'Client-side redirect with dynamic value — open redirect risk',
        severity: 'medium',
        file, line: i + 1,
        vuln: 'Client-Side — Open Redirect',
        description: 'window.location or router.push is set from a dynamic expression that may include user-supplied data (URL params, props, query string). An attacker can craft a link that redirects to a malicious site, enabling phishing or OAuth token harvesting.',
        remediation: 'Validate redirect URLs against an allowlist before redirecting:\n  const ALLOWED = ["/dashboard", "/profile"];\n  if (ALLOWED.includes(next)) router.push(next);\nNever redirect to an absolute URL from user input.',
        cwe: 'CWE-601',
      });
    }
  }

  // postMessage listener without origin check
  if (POST_MESSAGE_LISTENER_RE.test(content)) {
    const listenerIdx = content.search(POST_MESSAGE_LISTENER_RE);
    // Check the surrounding ~500 chars for an origin check
    const ctx = content.slice(listenerIdx, Math.min(content.length, listenerIdx + 600));
    if (!ORIGIN_CHECK_RE.test(ctx)) {
      findings.push({
        id: `client-side:POSTMESSAGE_NO_ORIGIN:${file}:${_lineOf(content, listenerIdx)}`,
        title: 'postMessage listener does not check event.origin',
        severity: 'medium',
        file, line: _lineOf(content, listenerIdx),
        vuln: 'Client-Side — postMessage without Origin Check',
        description: 'A window.addEventListener("message") handler processes messages without validating event.origin. Any website can send a message to this page and have it processed as if it came from a trusted source, enabling cross-origin data injection or UI redress attacks.',
        remediation: 'Add an origin check at the top of the handler:\n  window.addEventListener("message", (event) => {\n    if (event.origin !== "https://your-trusted-domain.com") return;\n    // process event.data\n  });',
        cwe: 'CWE-346',
      });
    }
  }

  // eval / Function constructor in client code
  for (let i = 0; i < lines.length; i++) {
    if (CLIENT_EVAL_RE.test(lines[i]) || FUNCTION_CONSTRUCTOR_RE.test(lines[i])) {
      findings.push({
        id: `client-side:CLIENT_EVAL:${file}:${i + 1}`,
        title: 'eval() or dynamic Function() in client-side code',
        severity: 'high',
        file, line: i + 1,
        vuln: 'Client-Side — eval with Dynamic Input',
        description: 'eval() or new Function() executes strings as JavaScript. In a browser context, this can be exploited via XSS, prototype pollution, or user-controlled inputs to execute arbitrary code and bypass Content-Security-Policy.',
        remediation: 'Eliminate eval(). Use JSON.parse() for data, specific function maps for dynamic dispatch, or a safe expression evaluator if math is required. Set Content-Security-Policy: script-src \'self\' to prevent eval() at the browser level.',
        cwe: 'CWE-95',
      });
    }
  }

  return findings;
}

export { scanClientSide };
