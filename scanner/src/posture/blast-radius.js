// Blast-radius and cost framing.
//
// Decorates each finding with a plain-English narrative of who/what is
// affected if it's exploited. Uses signals already extractable from the
// scan target — no LLM call, no network.
//
// Cost model (4 components, summed):
//   1. Incident response floor  — IR retainer + forensics (always incurred)
//   2. Notification cost        — $5/affected user (FTC/GDPR benchmark)
//   3. CWE-specific damage band — sourced from public settlements
//   4. Regulatory fine estimate — GDPR/CCPA/HIPAA/PCI per data class
//
// Scale factors applied on top:
//   - User count tier     (auto-estimated from project signals)
//   - Data class          (PHI 3×, payment 2×, PII 1×)
//   - Route exposure      (admin-only 0.3×, internal 0.6×, public 1×)
//
// Decoration shape:
//   blastRadius: {
//     scope: 'paying-users' | 'all-users' | 'admin-only' | 'public',
//     dataAtRisk: ['PII', 'payment', 'auth-tokens'],
//     userCount: 5000,
//     dollarLow: 50000,
//     dollarHigh: 500000,
//     components: { ir: ..., notification: ..., damage: ..., regulatory: ... },
//     narrative: "..."
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── CWE damage bands (sourced from public incident settlements) ───────────────
// best_case = exploited at small scale, caught quickly
// likely_case = median for a small SaaS/startup
// worst_case = exploited at scale before detection

const CWE_BANDS = {
  'CWE-89':   { low: 5_000,  mid: 75_000,   high: 5_000_000,  regulatory: 'GDPR/CCPA/HIPAA' },
  'CWE-78':   { low: 10_000, mid: 150_000,   high: 10_000_000, regulatory: 'GDPR+SEC' },
  'CWE-22':   { low: 2_000,  mid: 40_000,    high: 1_000_000,  regulatory: 'GDPR Art.33' },
  'CWE-918':  { low: 1_000,  mid: 60_000,    high: 50_000_000, regulatory: 'GLBA/GDPR/CCPA' },
  'CWE-79':   { low: 1_000,  mid: 25_000,    high: 500_000,    regulatory: 'GDPR/CCPA' },
  'CWE-639':  { low: 5_000,  mid: 100_000,   high: 2_000_000,  regulatory: 'GDPR/CCPA' },
  'CWE-352':  { low: 500,    mid: 15_000,    high: 500_000,    regulatory: 'GDPR Art.32' },
  'CWE-915':  { low: 2_000,  mid: 50_000,    high: 1_000_000,  regulatory: 'PCI-DSS' },
  'CWE-287':  { low: 10_000, mid: 200_000,   high: 10_000_000, regulatory: 'GDPR Art.32' },
  'CWE-345':  { low: 1_000,  mid: 30_000,    high: 2_000_000,  regulatory: 'PCI-DSS' },
  'CWE-502':  { low: 20_000, mid: 250_000,   high: 20_000_000, regulatory: 'GDPR+SEC' },
  'CWE-1321': { low: 500,    mid: 20_000,    high: 1_000_000,  regulatory: 'varies' },
  'CWE-798':  { low: 5_000,  mid: 80_000,    high: 5_000_000,  regulatory: 'GDPR Art.32' },
  'CWE-601':  { low: 500,    mid: 15_000,    high: 500_000,    regulatory: 'GDPR' },
  'CWE-611':  { low: 2_000,  mid: 50_000,    high: 2_000_000,  regulatory: 'GDPR Art.33' },
  'CWE-862':  { low: 5_000,  mid: 100_000,   high: 5_000_000,  regulatory: 'GDPR/CCPA' },
  'CWE-613':  { low: 2_000,  mid: 40_000,    high: 1_000_000,  regulatory: 'GDPR Art.32' },
  'CWE-209':  { low: 500,    mid: 10_000,    high: 200_000,    regulatory: 'GDPR' },
  'CWE-434':  { low: 5_000,  mid: 75_000,    high: 5_000_000,  regulatory: 'GDPR Art.33' },
  'CWE-400':  { low: 200,    mid: 5_000,     high: 100_000,    regulatory: 'provider T&C' },
  'LLM01':    { low: 500,    mid: 40_000,    high: 5_000_000,  regulatory: 'NIST AI 600-1' },
  'LLM02':    { low: 1_000,  mid: 50_000,    high: 3_000_000,  regulatory: 'GDPR/CCPA' },
  'LLM10':    { low: 200,    mid: 5_000,     high: 100_000,    regulatory: 'provider T&C' },
  'DEFAULT':  { low: 500,    mid: 10_000,    high: 200_000,    regulatory: 'varies' },
};

// Vuln name → CWE mapping for findings that don't carry a cwe field.
const VULN_TO_CWE = {
  'sql injection':              'CWE-89',
  'nosql injection':            'CWE-89',
  'command injection':          'CWE-78',
  'os command':                 'CWE-78',
  'path traversal':             'CWE-22',
  'zip slip':                   'CWE-22',
  'ssrf':                       'CWE-918',
  'server-side request':        'CWE-918',
  'xss':                        'CWE-79',
  'cross-site scripting':       'CWE-79',
  'dangerouslysetinnerhtml':    'CWE-79',
  'idor':                       'CWE-639',
  'insecure direct object':     'CWE-639',
  'csrf':                       'CWE-352',
  'mass assignment':            'CWE-915',
  'authentication bypass':      'CWE-287',
  'broken authentication':      'CWE-287',
  'jwt':                        'CWE-287',
  'webhook':                    'CWE-345',
  'signature missing':          'CWE-345',
  'deserialization':            'CWE-502',
  'prototype pollution':        'CWE-1321',
  'hardcoded':                  'CWE-798',
  'open redirect':              'CWE-601',
  'xxe':                        'CWE-611',
  'xml external':               'CWE-611',
  'missing authorization':      'CWE-862',
  'broken access control':      'CWE-862',
  'missing auth':               'CWE-862',
  'session fixation':           'CWE-613',
  'error message':              'CWE-209',
  'stack trace':                'CWE-209',
  'file upload':                'CWE-434',
  'rate limit':                 'CWE-400',
  'prompt injection':           'LLM01',
  'llm output':                 'LLM02',
  'max_tokens':                 'LLM10',
  'unbounded consumption':      'LLM10',
};

// ── project-signal collection ─────────────────────────────────────────────────

function readSafe(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }

export function collectProjectSignals(scanRoot) {
  const sig = {
    hasStripe: false,
    hasAuth: false,
    hasUserTable: false,
    hasS3: false,
    hasPII: false,
    hasPHI: false,
    hasSecrets: false,
    hasAnalytics: false,
    hasEnterpriseSignals: false,   // B2B indicators → smaller but higher-value user base
    estimatedUsers: null,
    revenueIndicator: null,        // 'startup' | 'growth' | 'scale'
    dependencies: new Set(),
  };

  const manifests = [
    'package.json', 'requirements.txt', 'pyproject.toml',
    'Gemfile', 'go.mod', 'composer.json', 'Cargo.toml',
  ];
  for (const m of manifests) {
    const text = readSafe(path.join(scanRoot, m));
    if (!text) continue;
    if (/stripe|paddle|chargebee|square|braintree|lemonsqueezy/i.test(text)) sig.hasStripe = true;
    if (/clerk|next-auth|@auth\/|lucia-auth|passport|firebase-auth|auth0|supabase|better-auth/i.test(text)) sig.hasAuth = true;
    if (/aws-sdk|@aws-sdk\/client-s3|boto3|google-cloud-storage|@google-cloud\/storage/i.test(text)) sig.hasS3 = true;
    if (/posthog|mixpanel|amplitude|segment|ga4|@analytics/i.test(text)) sig.hasAnalytics = true;
    if (/linear|jira|salesforce|hubspot|zendesk/i.test(text)) sig.hasEnterpriseSignals = true;
    for (const m2 of text.matchAll(/"([\w@/-]+)"\s*:/g)) sig.dependencies.add(m2[1]);
  }

  // Schema / migration heuristic.
  for (const f of ['schema.prisma', 'prisma/schema.prisma', 'db/schema.ts', 'db/schema.js',
                   'supabase/migrations', 'migrations']) {
    const fp = path.join(scanRoot, f);
    if (!fs.existsSync(fp)) continue;
    let text = '';
    try {
      const stat = fs.statSync(fp);
      if (stat.isDirectory()) {
        const files = fs.readdirSync(fp).slice(0, 20);
        for (const sub of files) text += readSafe(path.join(fp, sub));
      } else text = readSafe(fp);
    } catch {}
    if (/\b(?:User|users|profiles?|accounts?)\b/.test(text)) sig.hasUserTable = true;
    if (/\b(?:email|phone|address|ssn|date_of_birth|dob|national_id)\b/i.test(text)) sig.hasPII = true;
    if (/\b(?:diagnosis|medical|patient|prescription|hipaa|health_record|mrn)\b/i.test(text)) sig.hasPHI = true;
    if (/\b(?:card|payment|invoice|charge|subscription|stripe_customer)\b/i.test(text)) sig.hasStripe = true;
  }

  // Env files present → has production credentials → likely live.
  for (const f of ['.env', '.env.local', '.env.production']) {
    if (fs.existsSync(path.join(scanRoot, f))) sig.hasSecrets = true;
  }

  // Estimate user tier from project signals.
  // This is deliberately conservative — we'd rather understate than panic.
  sig.estimatedUsers = estimateUserCount(sig);
  sig.revenueIndicator = estimateRevenueTier(sig);

  return sig;
}

function estimateUserCount(sig) {
  // Enterprise B2B: fewer users but higher-value accounts.
  if (sig.hasEnterpriseSignals && !sig.hasAnalytics) return 200;
  // Consumer app with analytics: meaningful user base.
  if (sig.hasAnalytics && sig.hasAuth) return 10_000;
  // Has auth + payment: paying users, assume small SaaS.
  if (sig.hasStripe && sig.hasAuth) return 500;
  // Has auth but no payment signals: freemium / open.
  if (sig.hasAuth && sig.hasUserTable) return 2_000;
  // API-only or no auth: internal tool or small project.
  return 100;
}

function estimateRevenueTier(sig) {
  if (sig.hasStripe && sig.hasEnterpriseSignals) return 'growth';
  if (sig.hasStripe) return 'startup';
  return 'pre-revenue';
}

// ── user-count scale factor ───────────────────────────────────────────────────
// Scales the CWE damage band proportionally to the affected population.
// Source: notification costs ($5/user FTC benchmark), legal fees scale sublinearly.

function userScaleFactor(userCount) {
  if (userCount <= 50)      return 0.15;
  if (userCount <= 200)     return 0.30;
  if (userCount <= 1_000)   return 0.55;
  if (userCount <= 5_000)   return 1.00;   // baseline
  if (userCount <= 25_000)  return 1.80;
  if (userCount <= 100_000) return 3.50;
  return 6.00;
}

// ── data-class multiplier ─────────────────────────────────────────────────────
// PHI breaches face HIPAA minimum $100/record + mandatory OCR investigation.
// Payment breaches face PCI-DSS fines + chargeback liability.

function dataClassMultiplier(sig, data) {
  if (sig.hasPHI || data.includes('PHI')) return 3.0;
  if (sig.hasStripe && data.includes('payment')) return 2.0;
  if (sig.hasPII || data.includes('PII')) return 1.0;
  return 0.7;   // secrets/config exposure without user data
}

// ── route exposure factor ─────────────────────────────────────────────────────

function routeExposureFactor(finding) {
  const file = (finding.file || '').toLowerCase();
  if (/\badmin\b|\binternal\b|\bbackoffice\b|\bstaff\b/.test(file)) return 0.3;
  if (/\binternal\b|\bprivate\b/.test(file)) return 0.6;
  return 1.0;
}

// ── incident response floor ───────────────────────────────────────────────────
// Even a small breach incurs: IR retainer call-out, forensics hours,
// legal opinion, notification letter drafting. FTC and state AG investigations
// add mandatory filing costs even for small companies.

function irFloor(sig) {
  if (sig.hasPHI) return 25_000;    // HIPAA breach = mandatory OCR report + legal
  if (sig.hasStripe) return 15_000; // PCI-DSS incident response requirement
  return 8_000;                     // basic IR retainer + notification drafting
}

// ── notification cost ─────────────────────────────────────────────────────────
// $5/user is the FTC benchmark (first-class mail notification + credit monitoring offer).
// GDPR Art.33 requires notification within 72h regardless of user count.

function notificationCost(userCount, scope) {
  const affected = scope === 'admin-only' ? Math.min(userCount, 20) : userCount;
  return Math.round(affected * 5);
}

// ── CWE lookup ────────────────────────────────────────────────────────────────

function getCweBand(finding) {
  // Prefer the finding's explicit CWE field.
  if (finding.cwe) {
    const band = CWE_BANDS[finding.cwe];
    if (band) return { cwe: finding.cwe, ...band };
  }
  // Fall back to vuln-name matching.
  const vuln = (finding.vuln || finding.title || '').toLowerCase();
  for (const [kw, cwe] of Object.entries(VULN_TO_CWE)) {
    if (vuln.includes(kw)) {
      const band = CWE_BANDS[cwe];
      if (band) return { cwe, ...band };
    }
  }
  return { cwe: 'DEFAULT', ...CWE_BANDS.DEFAULT };
}

// ── scope & data inference ────────────────────────────────────────────────────

function inferScopeAndData(finding, signals) {
  const vuln = (finding.vuln || finding.title || '').toLowerCase();
  const file = (finding.file || '').toLowerCase();

  let scope = 'all-users';
  const data = [];

  if (/admin|internal|backoffice|staff/.test(file)) scope = 'admin-only';
  else if (/payment|billing|checkout|invoice/.test(file)) scope = 'paying-users';

  if (/sql|nosql|injection|idor|mass.assign|auth|deseri/.test(vuln)) data.push('PII');
  if (/payment|webhook|stripe|billing/.test(vuln) || signals.hasStripe) data.push('payment');
  if (/credential|hardcoded|secret|api.key/.test(vuln)) data.push('credentials');
  if (/command|rce|deseri|ssrf/.test(vuln)) data.push('rce');
  if (/auth.token|session|jwt|cookie/.test(vuln)) data.push('auth-tokens');
  if (/llm|prompt|max_tokens/.test(vuln)) data.push('llm-cost');
  if (signals.hasPHI) data.push('PHI');

  if (data.length === 0) data.push('config');
  return { scope, data };
}

// ── narrative builder ─────────────────────────────────────────────────────────

function fmtMoney(n) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `$${Math.round(n / 1_000)}k`;
  return `$${n}`;
}

function buildNarrative(finding, signals) {
  const band = getCweBand(finding);
  if (!band) return null;

  const { scope, data } = inferScopeAndData(finding, signals);
  const userCount = signals.estimatedUsers || 1_000;
  const scaleFactor = userScaleFactor(userCount);
  const dataMult = dataClassMultiplier(signals, data);
  const routeFactor = routeExposureFactor(finding);

  // Component 1: incident response floor (fixed regardless of scale).
  const irCost = irFloor(signals);

  // Component 2: notification cost (scales with affected user count).
  const notifCost = notificationCost(userCount, scope);

  // Component 3: CWE-specific damage (scaled by users, data class, route).
  const damageLow  = Math.round(band.low  * scaleFactor * dataMult * routeFactor);
  const damageHigh = Math.round(band.high * scaleFactor * dataMult * routeFactor);

  // Component 4: regulatory fine (always at least possible for real user data).
  const hasPenalty = data.some(d => ['PII','payment','PHI','auth-tokens'].includes(d));
  const regLow  = hasPenalty ? Math.round(band.low  * 0.2 * dataMult) : 0;
  const regHigh = hasPenalty ? Math.round(band.high * 0.3 * dataMult) : 0;

  const dollarLow  = irCost + notifCost + damageLow  + regLow;
  const dollarHigh = irCost + notifCost + damageHigh + regHigh;

  const dataPhrase =
    data.includes('rce')         ? 'full server compromise (remote code execution)' :
    data.includes('payment')     ? `payment data for ~${userCount.toLocaleString()} users` :
    data.includes('PHI')         ? `health records for ~${userCount.toLocaleString()} patients` :
    data.includes('PII')         ? `PII for ~${userCount.toLocaleString()} users` :
    data.includes('credentials') ? 'production credentials and API keys' :
    data.includes('auth-tokens') ? `session tokens for ~${userCount.toLocaleString()} users` :
    data.includes('llm-cost')    ? 'unbounded LLM API spend' :
    'configuration / internal data';

  const line = finding.line || finding.source?.line || finding.sink?.line || 0;
  const narrative =
    `${finding.vuln || finding.title} on \`${finding.file}:${line}\` could ` +
    `${data.includes('rce') ? 'lead to' : 'expose'} ${dataPhrase}. ` +
    `Estimated cost if exploited: ${fmtMoney(dollarLow)}–${fmtMoney(dollarHigh)} ` +
    `(IR: ${fmtMoney(irCost)}, notification: ${fmtMoney(notifCost)}, ` +
    `damage: ${fmtMoney(damageLow)}–${fmtMoney(damageHigh)}` +
    (hasPenalty ? `, regulatory: ${fmtMoney(regLow)}–${fmtMoney(regHigh)}` : '') +
    `).`;

  return {
    scope,
    dataAtRisk: data,
    userCount,
    dollarLow,
    dollarHigh,
    components: { ir: irCost, notification: notifCost, damageLow, damageHigh, regLow, regHigh },
    narrative,
  };
}

// ── public API ────────────────────────────────────────────────────────────────

export function enrichWithBlastRadius(scan, scanRoot) {
  const signals = collectProjectSignals(scanRoot || process.cwd());
  let decorated = 0;
  for (const bucket of ['findings', 'secrets', 'logicVulns', 'supplyChain']) {
    for (const f of (scan[bucket] || [])) {
      const br = buildNarrative(f, signals);
      if (br) { f.blastRadius = br; decorated++; }
    }
  }
  scan.blastRadiusSignals = {
    hasStripe: signals.hasStripe,
    hasAuth: signals.hasAuth,
    hasUserTable: signals.hasUserTable,
    hasPII: signals.hasPII,
    hasPHI: signals.hasPHI,
    hasS3: signals.hasS3,
    estimatedUsers: signals.estimatedUsers,
    revenueIndicator: signals.revenueIndicator,
  };
  return { decorated, signals };
}
