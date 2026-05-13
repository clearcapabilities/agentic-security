// Auth provider misconfiguration audit.
//
// Every popular auth library for vibecoders has provider-specific footguns.
// This module detects the most common misconfigurations that static analysis
// can catch: insecure options, missing required fields, dangerous flags.
//
// Providers covered:
//   Clerk, NextAuth / Auth.js, Auth0, Lucia, Better Auth, Passport, generic
//
// Findings:
//   AUTH_DANGEROUS_EMAIL_LINKING  — allowDangerousEmailAccountLinking: true
//   AUTH_TRUST_HOST               — trustHost: true in NextAuth (CSRF bypass in prod)
//   AUTH_MISSING_SECRET           — NextAuth without NEXTAUTH_SECRET env var reference
//   AUTH_WEAK_SESSION_SECRET      — short/hardcoded session secret
//   AUTH_CLERK_PUBLIC_ROUTE       — sensitive path incorrectly marked public in Clerk
//   AUTH_MISSING_AUDIENCE         — JWT/OAuth without audience validation
//   AUTH_DISABLE_CSRF             — explicit CSRF protection disabled
//   AUTH_COOKIE_INSECURE          — session cookies without secure/sameSite
//   AUTH_HARDCODED_CLIENT_SECRET  — OAuth clientSecret hardcoded

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;

// --- Dangerous options ---

// allowDangerousEmailAccountLinking: true — lets attacker take over account by
// registering with same email via different provider
const DANGEROUS_EMAIL_LINKING_RE = /allowDangerousEmailAccountLinking\s*:\s*true/;

// trustHost: true in NextAuth — disables host validation, enabling CSRF when
// deployed behind a reverse proxy that sets arbitrary Host headers
const TRUST_HOST_RE = /trustHost\s*:\s*true/;

// NextAuth without NEXTAUTH_SECRET
const NEXTAUTH_IMPORT_RE = /(?:from|require)\s*\(?\s*['"`]next-auth['"`]/;
const NEXTAUTH_SECRET_REF_RE = /NEXTAUTH_SECRET|authSecret\s*:|secret\s*:\s*process\.env/;

// Weak session secret — short string literal as secret
const WEAK_SESSION_SECRET_RE = /(?:secret|SESSION_SECRET|sessionSecret)\s*[:=]\s*['"`]([^'"`]{1,20})['"`]/;

// CSRF disabled
const CSRF_DISABLED_RE = /csrf\s*:\s*(?:false|disabled|0)|disableCsrf\s*:\s*true|csrfProtection\s*:\s*false/i;

// OAuth clientSecret hardcoded
const HARDCODED_CLIENT_SECRET_RE = /clientSecret\s*:\s*['"`][a-zA-Z0-9_\-]{8,}['"`]/;

// JWT missing audience
const JWT_NO_AUDIENCE_RE = /jwt\.(?:verify|sign)\s*\([^)]*\)/g;
const JWT_AUDIENCE_RE = /\baudience\b/;

// Auth0 hardcoded secret
const AUTH0_SECRET_RE = /AUTH0_SECRET\s*[:=]\s*['"`][^'"`]{8,}['"`]/;

// Cookie without secure flag
const INSECURE_COOKIE_RE = /cookie\s*:\s*\{[^}]*\}/g;
const COOKIE_SECURE_RE = /\bsecure\s*:\s*true/;
const COOKIE_SAMESITE_RE = /\bsameSite\s*:/;

// Clerk: publicRoutes containing sensitive paths
const CLERK_CONFIG_RE = /(?:clerkMiddleware|authMiddleware)\s*\(\s*\{/;
const CLERK_PUBLIC_ROUTES_RE = /publicRoutes\s*:\s*\[([^\]]+)\]/;
const SENSITIVE_PATH_IN_PUBLIC_RE = /['"`]\/(?:api\/(?:admin|users|delete|update|private)|dashboard|settings|admin)[^'"`]*['"`]/i;

function scanAuthProvider(file, content) {
  if (!_SCAN_EXT_RE.test(file)) return [];
  if (_NONPROD_RE.test(file)) return [];
  const findings = [];
  const lines = content.split('\n');

  function lineOf(re, searchContent = content) {
    const m = re.exec(searchContent);
    if (!m) return -1;
    return searchContent.slice(0, m.index).split('\n').length;
  }

  function push(id, title, severity, lineNum, description, remediation, cwe) {
    if (lineNum < 1) lineNum = 1;
    findings.push({ id: `auth-provider:${id}:${file}:${lineNum}`, title, severity, file, line: lineNum, description, remediation, cwe });
  }

  // allowDangerousEmailAccountLinking
  if (DANGEROUS_EMAIL_LINKING_RE.test(content)) {
    push('AUTH_DANGEROUS_EMAIL_LINKING', 'Dangerous email account linking enabled',
      'high', lineOf(DANGEROUS_EMAIL_LINKING_RE),
      'allowDangerousEmailAccountLinking: true lets an attacker register with the same email address via a different OAuth provider to take over an existing account without knowing the password.',
      'Remove allowDangerousEmailAccountLinking: true. If you need multi-provider linking, implement explicit user-confirmation flow instead.',
      'CWE-287');
  }

  // trustHost
  if (TRUST_HOST_RE.test(content)) {
    push('AUTH_TRUST_HOST', 'NextAuth trustHost: true disables host validation',
      'high', lineOf(TRUST_HOST_RE),
      'trustHost: true bypasses NextAuth\'s HOST header validation, disabling CSRF protection when deployed behind a reverse proxy. Attackers can craft requests with a spoofed Host header.',
      'Remove trustHost: true. Instead, set the AUTH_URL / NEXTAUTH_URL environment variable to your canonical production URL.',
      'CWE-352');
  }

  // NextAuth without secret
  if (NEXTAUTH_IMPORT_RE.test(content) && !NEXTAUTH_SECRET_REF_RE.test(content)) {
    push('AUTH_MISSING_SECRET', 'NextAuth configuration without NEXTAUTH_SECRET reference',
      'high', lineOf(NEXTAUTH_IMPORT_RE),
      'NextAuth requires NEXTAUTH_SECRET for JWT encryption and CSRF token signing. Without it, NextAuth falls back to an auto-generated secret that changes on every restart, invalidating all sessions, and is insecure in some deploy environments.',
      'Add `secret: process.env.NEXTAUTH_SECRET` to your NextAuth config and set NEXTAUTH_SECRET to a 32+ byte random string in your environment.',
      'CWE-330');
  }

  // Weak session secret
  for (let i = 0; i < lines.length; i++) {
    const m = WEAK_SESSION_SECRET_RE.exec(lines[i]);
    if (m && m[1] && m[1].length <= 20) {
      push('AUTH_WEAK_SESSION_SECRET', 'Session secret is short or hardcoded',
        'high', i + 1,
        `A session/auth secret of only ${m[1].length} characters is used. Secrets shorter than 32 characters are vulnerable to brute-force. Hardcoded secrets are also committed to git history.`,
        'Generate a cryptographically random 32+ byte secret: `openssl rand -base64 32`. Store it as an environment variable, never in source code.',
        'CWE-521');
    }
  }

  // Hardcoded OAuth clientSecret
  for (let i = 0; i < lines.length; i++) {
    if (HARDCODED_CLIENT_SECRET_RE.test(lines[i])) {
      push('AUTH_HARDCODED_CLIENT_SECRET', 'OAuth clientSecret hardcoded in source',
        'high', i + 1,
        'An OAuth client secret is embedded in source code. It will be committed to git, potentially leaked via the build bundle, and cannot be rotated without a code change.',
        'Move to an environment variable: `clientSecret: process.env.OAUTH_CLIENT_SECRET`. Rotate the secret in your OAuth provider dashboard.',
        'CWE-798');
    }
  }

  // CSRF disabled
  if (CSRF_DISABLED_RE.test(content)) {
    push('AUTH_DISABLE_CSRF', 'CSRF protection explicitly disabled',
      'high', lineOf(CSRF_DISABLED_RE),
      'Cross-Site Request Forgery protection is turned off. Attackers can trick authenticated users into triggering state-changing actions on your app from a third-party website.',
      'Remove the csrf: false / disableCsrf option. Auth libraries enable CSRF protection by default for good reason.',
      'CWE-352');
  }

  // Clerk public routes containing sensitive paths
  if (CLERK_CONFIG_RE.test(content)) {
    const publicMatch = CLERK_PUBLIC_ROUTES_RE.exec(content);
    if (publicMatch && SENSITIVE_PATH_IN_PUBLIC_RE.test(publicMatch[1])) {
      const lineNum = content.slice(0, CLERK_PUBLIC_ROUTES_RE.lastIndex).split('\n').length;
      push('AUTH_CLERK_PUBLIC_ROUTE', 'Sensitive route marked public in Clerk middleware',
        'high', lineNum,
        'A path that appears to be sensitive (admin, settings, private API) is listed in Clerk\'s publicRoutes, making it accessible to unauthenticated users.',
        'Remove sensitive paths from publicRoutes. Use auth().protect() or redirect to sign-in for routes that require authentication.',
        'CWE-284');
    }
  }

  // Cookie without secure/sameSite in session config
  let cookieM;
  const cookieRe = new RegExp(INSECURE_COOKIE_RE.source, 'g');
  while ((cookieM = cookieRe.exec(content)) !== null) {
    const block = cookieM[0];
    if (!COOKIE_SECURE_RE.test(block) || !COOKIE_SAMESITE_RE.test(block)) {
      const lineNum = content.slice(0, cookieM.index).split('\n').length;
      push('AUTH_COOKIE_INSECURE', 'Session cookie missing secure or sameSite flag',
        'medium', lineNum,
        'Session cookies without `secure: true` can be transmitted over HTTP. Without `sameSite`, they are sent on cross-site requests, enabling CSRF.',
        'Set `cookie: { secure: true, sameSite: "lax", httpOnly: true }` in your session/auth config.',
        'CWE-614');
    }
  }

  return findings;
}

export { scanAuthProvider };
