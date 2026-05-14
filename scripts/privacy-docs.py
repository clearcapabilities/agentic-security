#!/usr/bin/env python3
"""
privacy-docs.py — detect data collection in the codebase, then generate
                  privacy policy + cookie consent component scaffolds.

Vibe-coders don't have lawyers. They have legal exposure they don't know
about. This script reduces the gap by:

  1. Scanning the codebase for known data-collecting providers (Stripe,
     Supabase, Sentry, PostHog, Mixpanel, Google Analytics, Cloudflare
     Analytics, Auth0, Clerk, OpenAI, Anthropic, ...).
  2. Mapping each detection to a privacy-policy section (what data the
     provider receives + their DPA URL + their sub-processor list URL).
  3. Generating PRIVACY.md tailored to YOUR actual stack.
  4. Optionally generating a React cookie-consent component matched to
     your detected analytics providers.

Not legal advice. Treat as a starting template; have a lawyer review for
your jurisdiction before going live.

Usage:
  python3 scripts/privacy-docs.py
  python3 scripts/privacy-docs.py --company "Acme Inc." --jurisdiction US-CA
  python3 scripts/privacy-docs.py --generate-banner
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Provider catalog — what each provider receives + their DPA/sub-processor URLs
# ─────────────────────────────────────────────────────────────────────────────

PROVIDERS = {
    "stripe": {
        "name": "Stripe",
        "deps": ["stripe", "@stripe/stripe-js", "@stripe/react-stripe-js"],
        "env_hints": ["STRIPE_"],
        "purpose": "Payment processing",
        "data_received": "Payment card details (handled by Stripe directly — your app never sees them under Stripe Elements), billing address, email, transaction amount.",
        "dpa_url": "https://stripe.com/legal/dpa",
        "subprocessors_url": "https://stripe.com/legal/privacy-center",
        "category": "payment",
        "cookies": "Stripe sets cookies for fraud detection (m, __stripe_mid, __stripe_sid)",
    },
    "supabase": {
        "name": "Supabase",
        "deps": ["@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"],
        "env_hints": ["SUPABASE_", "NEXT_PUBLIC_SUPABASE_"],
        "purpose": "Database, authentication, file storage",
        "data_received": "User credentials (email, password hash), all application data you write to Supabase tables, uploaded files.",
        "dpa_url": "https://supabase.com/legal/dpa",
        "subprocessors_url": "https://supabase.com/legal/subprocessors",
        "category": "infra",
        "cookies": "Supabase Auth sets a session cookie (`sb-<project>-auth-token`) for authenticated users",
    },
    "clerk": {
        "name": "Clerk",
        "deps": ["@clerk/nextjs", "@clerk/clerk-react", "@clerk/clerk-sdk-node"],
        "env_hints": ["CLERK_"],
        "purpose": "User authentication and identity management",
        "data_received": "Email address, name, profile picture, OAuth provider tokens, sign-in metadata (IP, user agent, timestamps).",
        "dpa_url": "https://clerk.com/legal/dpa",
        "subprocessors_url": "https://clerk.com/legal/subprocessors",
        "category": "auth",
        "cookies": "Clerk sets session cookies (`__session`, `__client_uat`) — strictly necessary",
    },
    "auth0": {
        "name": "Auth0",
        "deps": ["@auth0/nextjs-auth0", "auth0", "@auth0/auth0-react"],
        "env_hints": ["AUTH0_"],
        "purpose": "User authentication and identity management",
        "data_received": "Email, name, profile data, OAuth provider tokens, sign-in metadata.",
        "dpa_url": "https://auth0.com/docs/secure/data-privacy-and-compliance/gdpr",
        "subprocessors_url": "https://auth0.com/docs/secure/data-privacy-and-compliance/auth0-subprocessors",
        "category": "auth",
        "cookies": "Auth0 sets session cookies — strictly necessary",
    },
    "sentry": {
        "name": "Sentry",
        "deps": ["@sentry/nextjs", "@sentry/react", "@sentry/node", "@sentry/browser"],
        "env_hints": ["SENTRY_"],
        "purpose": "Error monitoring and performance tracking",
        "data_received": "Stack traces (may include user inputs that triggered errors), browser metadata, IP address (configurable), user identifiers (if `setUser` is called).",
        "dpa_url": "https://sentry.io/legal/dpa/",
        "subprocessors_url": "https://sentry.io/legal/subprocessors/",
        "category": "analytics",
        "cookies": "Sentry does not set cookies by default for browser monitoring",
    },
    "posthog": {
        "name": "PostHog",
        "deps": ["posthog-js", "posthog-node"],
        "env_hints": ["POSTHOG_", "NEXT_PUBLIC_POSTHOG_"],
        "purpose": "Product analytics and feature flags",
        "data_received": "Page views, button clicks, custom events you instrument, browser metadata, IP-derived geo, anonymous device ID.",
        "dpa_url": "https://posthog.com/dpa",
        "subprocessors_url": "https://posthog.com/handbook/company/security#subprocessors",
        "category": "analytics",
        "cookies": "PostHog sets a `ph_<key>_posthog` cookie containing the anonymous device ID",
    },
    "mixpanel": {
        "name": "Mixpanel",
        "deps": ["mixpanel-browser", "mixpanel"],
        "env_hints": ["MIXPANEL_"],
        "purpose": "Product analytics",
        "data_received": "Page views, custom events, browser metadata, anonymous distinct ID (or user ID if identified).",
        "dpa_url": "https://mixpanel.com/legal/mixpanel-dpa",
        "subprocessors_url": "https://mixpanel.com/legal/subprocessors",
        "category": "analytics",
        "cookies": "Mixpanel sets cookies for distinct-ID tracking",
    },
    "google-analytics": {
        "name": "Google Analytics (GA4)",
        "deps": ["@next/third-parties", "react-ga4", "@analytics/google-analytics"],
        "env_hints": ["NEXT_PUBLIC_GA_", "GA_MEASUREMENT_"],
        "purpose": "Web analytics",
        "data_received": "Page views, events, IP address (anonymized in EU when configured), client identifier, browser metadata.",
        "dpa_url": "https://business.safety.google/intl/en/processorterms/",
        "subprocessors_url": "https://business.safety.google/intl/en/subprocessors/",
        "category": "analytics",
        "cookies": "GA4 sets `_ga`, `_ga_<id>` cookies (1-2 years retention)",
    },
    "openai": {
        "name": "OpenAI",
        "deps": ["openai"],
        "env_hints": ["OPENAI_API_KEY"],
        "purpose": "LLM features (text generation, embeddings, ...)",
        "data_received": "The exact prompts and any user content passed to the API. Per OpenAI policy, API data is not used to train models (default).",
        "dpa_url": "https://openai.com/policies/data-processing-addendum",
        "subprocessors_url": "https://openai.com/policies/subprocessors",
        "category": "ai",
        "cookies": "No cookies (server-side only)",
    },
    "anthropic": {
        "name": "Anthropic",
        "deps": ["@anthropic-ai/sdk", "anthropic"],
        "env_hints": ["ANTHROPIC_API_KEY"],
        "purpose": "LLM features (Claude)",
        "data_received": "The exact prompts and any user content passed to the API. API data is retained per Anthropic's retention policy and not used to train models without opt-in.",
        "dpa_url": "https://www.anthropic.com/legal/dpa",
        "subprocessors_url": "https://www.anthropic.com/legal/subprocessors",
        "category": "ai",
        "cookies": "No cookies (server-side only)",
    },
    "vercel-analytics": {
        "name": "Vercel Analytics",
        "deps": ["@vercel/analytics", "@vercel/speed-insights"],
        "env_hints": [],
        "purpose": "Web analytics (privacy-preserving)",
        "data_received": "Page views, web vitals. No cross-site tracking; no third-party cookies.",
        "dpa_url": "https://vercel.com/legal/dpa",
        "subprocessors_url": "https://vercel.com/legal/subprocessors",
        "category": "analytics",
        "cookies": "No cookies",
    },
    "cloudflare-analytics": {
        "name": "Cloudflare Web Analytics",
        "deps": [],
        "env_hints": ["CLOUDFLARE_ANALYTICS"],
        "purpose": "Web analytics (privacy-preserving)",
        "data_received": "Page views, web vitals. No cookies; no fingerprinting.",
        "dpa_url": "https://www.cloudflare.com/cloudflare-customer-dpa/",
        "subprocessors_url": "https://www.cloudflare.com/gdpr/subprocessors/",
        "category": "analytics",
        "cookies": "No cookies",
    },
    "resend": {
        "name": "Resend",
        "deps": ["resend"],
        "env_hints": ["RESEND_API_KEY"],
        "purpose": "Transactional email delivery",
        "data_received": "Email addresses, email content, send/delivery/open/click events.",
        "dpa_url": "https://resend.com/legal/dpa",
        "subprocessors_url": "https://resend.com/legal/subprocessors",
        "category": "email",
        "cookies": "No cookies",
    },
    "sendgrid": {
        "name": "SendGrid (Twilio)",
        "deps": ["@sendgrid/mail"],
        "env_hints": ["SENDGRID_API_KEY"],
        "purpose": "Transactional email delivery",
        "data_received": "Email addresses, email content, engagement events.",
        "dpa_url": "https://www.twilio.com/legal/data-protection-addendum",
        "subprocessors_url": "https://www.twilio.com/legal/sub-processors",
        "category": "email",
        "cookies": "No cookies (server-side)",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_providers(cwd: Path) -> list[dict]:
    detected = []
    detected_names = set()

    pkg = cwd / "package.json"
    deps = {}
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        except Exception:
            pass

    env_content = ""
    for env_file in (".env", ".env.local", ".env.example", ".env.production"):
        p = cwd / env_file
        if p.exists():
            try:
                env_content += "\n" + p.read_text(errors="ignore")
            except Exception:
                pass

    for key, prov in PROVIDERS.items():
        match_via_dep = any(d in deps for d in prov["deps"])
        match_via_env = any(h in env_content for h in prov.get("env_hints", []))
        if match_via_dep or match_via_env:
            if prov["name"] not in detected_names:
                detected.append({**prov, "key": key, "matched_via": "dependency" if match_via_dep else "env_var"})
                detected_names.add(prov["name"])
    return detected


# ─────────────────────────────────────────────────────────────────────────────
# Renderers
# ─────────────────────────────────────────────────────────────────────────────

def render_privacy_policy(company: str, contact: str, providers: list[dict], jurisdiction: str) -> str:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    third_party_list = "\n".join(
        f"### {p['name']}\n\n- **Purpose:** {p['purpose']}\n- **Data shared:** {p['data_received']}\n- **DPA:** [{p['dpa_url']}]({p['dpa_url']})\n- **Sub-processors:** [{p['subprocessors_url']}]({p['subprocessors_url']})\n"
        for p in providers
    ) or "_(no third-party data processors detected)_"

    jurisdiction_clause = {
        "EU":    "Under the GDPR (Regulation 2016/679), you have the right to access, rectify, erase, restrict, and port your personal data, and to object to processing. You can lodge a complaint with your supervisory authority.",
        "US-CA": "Under the California Consumer Privacy Act (CCPA), you have the right to know what personal information we collect, request deletion, opt out of the sale of personal information (we do not sell), and to non-discrimination for exercising these rights.",
        "UK":    "Under the UK GDPR and Data Protection Act 2018, you have the same rights as listed under the EU GDPR. You can lodge a complaint with the Information Commissioner's Office (ICO).",
        "OTHER": "You may have data protection rights under your local jurisdiction. Contact us to exercise them.",
    }.get(jurisdiction, "You may have data protection rights under your local jurisdiction. Contact us to exercise them.")

    return f"""# Privacy Policy

*Last updated: {today}*

This Privacy Policy describes how **{company}** (\"we\", \"our\", \"us\") collects, uses, and shares your personal information when you use our service.

> **Important:** This policy is a starting template generated from our service's actual third-party integrations. It is **not legal advice**. Please review with qualified counsel before relying on it for compliance.

## What we collect

- **Account information** you provide (email address, name, password — stored hashed).
- **Content** you submit through the service.
- **Usage data** — actions you take in the application, sufficient to operate, secure, and improve the service.
- **Technical data** — IP address, browser type, device identifier, timestamps.

## How we use it

- To **provide the service** you signed up for.
- To **secure the service** — detect abuse, prevent fraud, investigate incidents.
- To **communicate with you** — service notifications, security alerts, billing.
- To **improve the service** — aggregate analytics, debug error reports.

We do not sell your personal data.

## Third-party data processors

The following processors receive specific data on our behalf, governed by data processing agreements:

{third_party_list}

## Cookies

The service uses cookies for:

- **Strictly necessary** — authentication sessions, CSRF protection. Cannot be disabled.
- **Functional** — remembering UI preferences. Set when you interact with relevant features.
- **Analytics** (if applicable) — anonymous usage analytics. You may opt out via the consent banner.

## Data retention

- **Active customer data:** retained for the duration of your account, plus 30 days after deletion.
- **Backups:** retained for 30 days for disaster recovery.
- **Audit logs:** retained for 12 months for security and compliance.
- **Anonymized analytics:** retained indefinitely.

## Your rights

{jurisdiction_clause}

To exercise any of these rights, email **{contact}**. We will respond within the timeline required by applicable law.

## Security

We follow industry-standard practices including encryption in transit (TLS 1.2+) and at rest (AES-256), least-access controls, and continuous static analysis. See our [security page](/security) for details.

## Children

The service is not directed to children under 13. We do not knowingly collect personal information from children under 13.

## Changes to this policy

We will notify you of material changes via email at least 30 days before they take effect.

## Contact

Questions? Email **{contact}**.

---

*This template was generated by [agentic-security](https://github.com/clearcapabilities/agentic-security) on {today}. The list of third-party processors above reflects what was actually detected in the codebase at that time.*
"""


def render_cookie_banner_react(providers: list[dict]) -> str:
    analytics = [p for p in providers if p["category"] == "analytics"]
    has_analytics = bool(analytics)
    providers_line = ", ".join(p["name"] for p in analytics) if analytics else "anonymous web analytics"

    return f'''// agentic-security: auto-generated cookie consent component
// Drop-in for Next.js App Router / React 18+.
// Stores the user's choice in localStorage and reflects it via the
// `analyticsConsent` event.

'use client';

import {{ useEffect, useState }} from 'react';

const STORAGE_KEY = 'consent-v1';

export function CookieBanner() {{
  const [open, setOpen] = useState(false);

  useEffect(() => {{
    const stored = typeof window !== 'undefined' && localStorage.getItem(STORAGE_KEY);
    if (!stored) setOpen(true);
  }}, []);

  const choose = (analytics: boolean) => {{
    localStorage.setItem(STORAGE_KEY, JSON.stringify({{ analytics, ts: Date.now() }}));
    window.dispatchEvent(new CustomEvent('analyticsConsent', {{ detail: {{ analytics }} }}));
    setOpen(false);
  }};

  if (!open) return null;
  return (
    <div role="dialog" aria-label="Cookie consent" style={{{{
      position: 'fixed', bottom: 16, left: 16, right: 16, maxWidth: 600,
      margin: '0 auto', background: '#1e293b', color: '#f8fafc',
      padding: 16, borderRadius: 8, boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
      fontFamily: 'system-ui, sans-serif', fontSize: 14,
    }}}}>
      <p style={{{{ margin: 0, marginBottom: 12 }}}}>
        We use strictly-necessary cookies to make the app work.{' '}
        {has_analytics and f'We can also use {providers_line} to understand how the app is used. ' or ''}
        See our <a href="/privacy" style={{{{ color: '#93c5fd' }}}}>Privacy Policy</a>.
      </p>
      <div style={{{{ display: 'flex', gap: 8 }}}}>
        <button onClick={{() => choose(false)}} style={{{{
          background: 'transparent', border: '1px solid #475569', color: 'inherit',
          padding: '6px 12px', borderRadius: 6, cursor: 'pointer',
        }}}}>Necessary only</button>
        <button onClick={{() => choose(true)}} style={{{{
          background: '#2563eb', border: 'none', color: 'white',
          padding: '6px 12px', borderRadius: 6, cursor: 'pointer',
        }}}}>Accept all</button>
      </div>
    </div>
  );
}}

// Use in your analytics setup:
//
//   import {{ getConsent }} from './cookie-banner-helpers';
//   if (getConsent().analytics) {{ initPosthog(); }}
//   window.addEventListener('analyticsConsent', (e) => {{
//     if (e.detail.analytics) initPosthog();
//   }});

export function getConsent(): {{ analytics: boolean }} {{
  if (typeof window === 'undefined') return {{ analytics: false }};
  try {{
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {{ analytics: false }};
  }} catch {{
    return {{ analytics: false }};
  }}
}}
'''


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate privacy policy + cookie banner from real stack detection.")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--company", default=None)
    parser.add_argument("--contact", default="privacy@example.com")
    parser.add_argument("--jurisdiction", choices=["EU", "US-CA", "UK", "OTHER"], default="OTHER")
    parser.add_argument("--output", default="PRIVACY.md")
    parser.add_argument("--generate-banner", action="store_true",
                        help="Also write a React cookie-consent component")
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()
    company = args.company or cwd.name

    providers = detect_providers(cwd)
    print(f"Detected {len(providers)} third-party data processor(s):")
    for p in providers:
        print(f"  - {p['name']:<25} ({p['category']}, matched via {p['matched_via']})")
    print()

    policy = render_privacy_policy(company, args.contact, providers, args.jurisdiction)
    out = cwd / args.output
    out.write_text(policy)
    print(f"✓ Privacy policy template: {out.relative_to(cwd) if str(out).startswith(str(cwd)) else out}")

    if args.generate_banner:
        component_dir = cwd / "components"
        component_dir.mkdir(exist_ok=True)
        comp_path = component_dir / "CookieBanner.tsx"
        comp_path.write_text(render_cookie_banner_react(providers))
        print(f"✓ Cookie banner component:  {comp_path.relative_to(cwd)}")
        print(f"  Mount once in your root layout:  <CookieBanner />")

    print()
    print("⚠️  These are TEMPLATES, not legal advice. Have a lawyer review for your")
    print("    jurisdiction before publishing. The processor list reflects what was")
    print("    detected at scan time — re-run when you add/remove providers.")


if __name__ == "__main__":
    main()
