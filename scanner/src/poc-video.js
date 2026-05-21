// Auto-recorded PoC video / exploit-runner generator (v0.74).
//
// For each finding with an `_exploitInput` (set by the v0.71 symbolic
// exploit prover), generate a self-contained script the user can run
// against their staging/dev environment to:
//
//   1. Drive the exploit live (HTTP request, browser interaction, etc.)
//   2. Capture the response showing the vuln triggered
//   3. Record the session as a video (Playwright) or transcript (curl)
//
// Three output formats:
//   - 'playwright' — TypeScript test that launches Chromium, records
//     video to a known path. Best for screenshareable evidence on
//     UI-driven exploits (DOM XSS, open redirect, CSRF, prototype
//     pollution).
//   - 'curl'       — bash script using curl with verbose tracing.
//     Best for backend exploits (SQLi, command injection, SSRF, path
//     traversal, deserialization).
//   - 'http'       — RFC 7230-style raw HTTP request + expected
//     response shape. Format-agnostic; pastable into any HTTP client.
//
// The generator does NOT execute anything — it produces a script the
// operator runs against their OWN environment. We never bundle a
// browser, never make network calls during generation.

const TEMPLATES = {
  playwright: _playwrightTemplate,
  curl:       _curlTemplate,
  http:       _httpTemplate,
};

/**
 * Pick the best default format for a given vuln family. UI-driven
 * exploits get playwright; backend exploits get curl.
 */
function _defaultFormatFor(cwe) {
  const ui = new Set(['CWE-79', 'CWE-601', 'CWE-352', 'CWE-1321']);
  return ui.has(cwe) ? 'playwright' : 'curl';
}

/**
 * Top-level entry. Returns a script string + a short filename hint.
 *
 *   finding: { cwe, vuln, file, line, _exploitInput, sink, ... }
 *   opts: {
 *     format: 'playwright' | 'curl' | 'http'   (default: by CWE)
 *     baseUrl: 'https://staging.example.com'   (default: http://localhost:3000)
 *     route:   '/api/admin/users'              (default: derived from finding)
 *     method:  'POST'                          (default: derived from finding)
 *   }
 */
export function generatePocScript(finding, opts = {}) {
  if (!finding) return { script: '', filename: 'poc.txt', format: null };
  const format = opts.format || _defaultFormatFor(finding.cwe);
  const baseUrl = opts.baseUrl || 'http://localhost:3000';
  const route = opts.route || _inferRoute(finding) || '/api/endpoint';
  const method = opts.method || _inferMethod(finding) || 'POST';
  const payload = finding._exploitInput || _fallbackPayload(finding.cwe);
  const template = TEMPLATES[format];
  if (!template) throw new Error(`Unknown format: ${format}`);
  const script = template({ finding, baseUrl, route, method, payload });
  const filename = _filenameFor(finding, format);
  return { script, filename, format, payload };
}

function _filenameFor(finding, format) {
  const ext = format === 'playwright' ? 'spec.ts'
    : format === 'curl' ? 'sh'
    : 'http';
  const slug = (finding.cwe || 'vuln').toLowerCase().replace(/[^a-z0-9]/g, '-');
  return `poc-${slug}-${finding.file?.replace(/[\/.]/g, '_') || 'finding'}.${ext}`;
}

function _inferRoute(f) {
  if (f.route) return f.route;
  if (typeof f.vuln === 'string') {
    const m = f.vuln.match(/(?:GET|POST|PUT|DELETE)\s+([\/\w:-]+)/i);
    if (m) return m[1];
  }
  return null;
}

function _inferMethod(f) {
  if (f.method) return f.method;
  if (typeof f.vuln === 'string') {
    const m = f.vuln.match(/\b(GET|POST|PUT|DELETE|PATCH)\b/i);
    if (m) return m[1].toUpperCase();
  }
  return null;
}

function _fallbackPayload(cwe) {
  const fallback = {
    'CWE-89':   "1' OR '1'='1",
    'CWE-78':   "; rm -rf /tmp/x",
    'CWE-79':   "<script>alert(1)</script>",
    'CWE-22':   "../../etc/passwd",
    'CWE-918':  "http://169.254.169.254/latest/meta-data/",
    'CWE-94':   "{{7*7}}",
    'CWE-601':  "//evil.example.com/phish",
    'CWE-1321': '{"__proto__":{"polluted":true}}',
  };
  return fallback[cwe] || '<attacker-payload>';
}

// ─── Templates ───────────────────────────────────────────────────────────

function _playwrightTemplate({ finding, baseUrl, route, method, payload }) {
  const safePayload = JSON.stringify(payload);
  return `// Auto-generated PoC by agentic-security ${new Date().toISOString().slice(0,10)}.
//
// Finding: ${finding.vuln} (${finding.cwe})
// Location: ${finding.file}:${finding.line}
//
// Run: npx playwright test ${_filenameFor(finding, 'playwright')}
//
// Records video to test-results/. The test PASSES when the exploit
// successfully triggers — flip the assertion if you're auditing the
// scanner's accuracy.

import { test, expect } from '@playwright/test';

test('PoC: ${finding.vuln}', async ({ page, request }) => {
  // Phase 1: take a clean baseline screenshot.
  await page.goto('${baseUrl}');
  await page.screenshot({ path: 'test-results/before.png', fullPage: true });

  // Phase 2: trigger the exploit.
  const PAYLOAD = ${safePayload};
  const response = await request.${method.toLowerCase()}('${baseUrl}${route}', {
    data: { input: PAYLOAD },
    failOnStatusCode: false,
  });

  // Phase 3: confirm the exploit fired. The exact assertion depends on
  // the vuln class — adjust before running.
  console.log('Response status:', response.status());
  const body = await response.text();
  console.log('Response (first 500 chars):', body.slice(0, 500));

  // Phase 4: capture the post-exploit state.
  await page.goto('${baseUrl}${route}');
  await page.screenshot({ path: 'test-results/after.png', fullPage: true });

  // Default assertion: the response should NOT 4xx-reject the payload.
  // If your sanitizer is in place, this assertion FAILS — which is the
  // outcome you want after applying the fix.
  expect(response.status()).toBeLessThan(400);
});
`;
}

function _curlTemplate({ finding, baseUrl, route, method, payload }) {
  return `#!/usr/bin/env bash
# Auto-generated PoC by agentic-security ${new Date().toISOString().slice(0,10)}.
#
# Finding: ${finding.vuln} (${finding.cwe})
# Location: ${finding.file}:${finding.line}
#
# Run: bash ${_filenameFor(finding, 'curl')}
#
# Exits 0 if the exploit appears to trigger; non-zero otherwise.
# Flip the assertion if you're auditing the scanner's accuracy.

set -euo pipefail

BASE_URL="\${BASE_URL:-${baseUrl}}"
ROUTE="${route}"
METHOD="${method}"
PAYLOAD=${JSON.stringify(payload)}

echo "→ Sending $METHOD $BASE_URL$ROUTE"
echo "  Payload: $PAYLOAD"
echo

RESPONSE=$(curl -sS -X "$METHOD" \\
  -H "Content-Type: application/json" \\
  -d "{\\"input\\":$(printf %s "$PAYLOAD" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}" \\
  -w "\\nHTTP_STATUS:%{http_code}\\n" \\
  "$BASE_URL$ROUTE" || true)

STATUS=$(echo "$RESPONSE" | grep '^HTTP_STATUS:' | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/^HTTP_STATUS:/d')

echo "← HTTP $STATUS"
echo "$BODY" | head -20
echo

# Default assertion: 2xx means the payload was accepted (i.e., the
# vulnerable path was reached). After fixing the vuln, this should 4xx.
if [ "$STATUS" -lt 400 ]; then
  echo "❌ PAYLOAD ACCEPTED ($STATUS) — vuln likely still present"
  exit 1
else
  echo "✓ Payload rejected ($STATUS) — sanitizer appears to be working"
  exit 0
fi
`;
}

function _httpTemplate({ finding, baseUrl, route, method, payload }) {
  const url = new URL(route, baseUrl);
  return `# Auto-generated PoC by agentic-security ${new Date().toISOString().slice(0,10)}.
# Finding: ${finding.vuln} (${finding.cwe})
# Location: ${finding.file}:${finding.line}
#
# Paste this into any HTTP client (Postman, Insomnia, vscode-rest-client).

${method} ${url.pathname}${url.search} HTTP/1.1
Host: ${url.host}
User-Agent: agentic-security-poc/1.0
Content-Type: application/json
Accept: application/json

{"input": ${JSON.stringify(payload)}}

###

# Expected outcome (pre-fix): server returns 2xx + vulnerable payload
# reaches the sink. After fix: server returns 4xx with a validation
# error. The CWE-specific signature to look for in the response:
#
${_responseSignatureFor(finding.cwe)}
`;
}

function _responseSignatureFor(cwe) {
  const sigs = {
    'CWE-89':   '# - SQL error containing "syntax" / "quote" / "OR"',
    'CWE-78':   '# - shell output of the injected command in body',
    'CWE-79':   '# - <script> tag echoed back into HTML response body',
    'CWE-22':   '# - file contents from outside the intended directory',
    'CWE-918':  '# - response body from the metadata IP',
    'CWE-601':  '# - Location: header pointing to the attacker domain',
  };
  return sigs[cwe] || '# - unexpected response shape consistent with the vuln class';
}

export const _internal = { _defaultFormatFor, _inferRoute, _inferMethod, _fallbackPayload, _playwrightTemplate, _curlTemplate, _httpTemplate };
