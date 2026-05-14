---
description: Generate a privacy policy template + cookie consent banner from YOUR actual stack. Detects every third-party data processor in your dependencies (Stripe, Supabase, Clerk, PostHog, Sentry, OpenAI, ...) and emits a tailored PRIVACY.md plus an optional React consent component.
argument-hint: "[--company NAME] [--contact EMAIL] [--jurisdiction EU|US-CA|UK|OTHER] [--generate-banner]"
---

# Privacy docs generator

You're collecting data. You need a privacy policy. You don't have a lawyer.

This command generates a privacy-policy template that's accurate to your actual integrations — not a generic template that says "we may use third-party services" while you secretly send data to 8 of them.

## What it does

1. **Scans your codebase** for known data-collecting providers:
   - Stripe, Supabase, Clerk, Auth0 — auth + payment
   - Sentry, PostHog, Mixpanel, Google Analytics, Vercel Analytics, Cloudflare Analytics — observability
   - OpenAI, Anthropic — AI
   - Resend, SendGrid — email
2. For each detected provider, includes a section in PRIVACY.md naming:
   - The provider
   - The purpose
   - The exact data they receive
   - Direct links to their DPA and sub-processor list
3. **Jurisdiction-tailored rights** — EU GDPR, UK GDPR, US-CA CCPA, or generic.
4. **Optional cookie banner** — React component with `Necessary only` and `Accept all` buttons, persisted to localStorage, broadcasts via `analyticsConsent` event so your analytics SDK can defer init.

## Usage

```bash
# Just generate the policy
/privacy-docs --company "Acme Inc." --contact privacy@acme.com --jurisdiction US-CA

# Also generate the React cookie banner component
/privacy-docs --generate-banner
```

## What you still need to do

- Have a lawyer review for your jurisdiction. The generated text is a **starting template**, not advice.
- Add use-case-specific clauses the template can't know about (e.g., children's data if you have under-13 users, biometric data, telehealth, financial-services regs).
- Re-run whenever you add or remove a processor — the list gets stale fast.

## Detection table

| Provider | Detected via |
|---|---|
| Stripe | `stripe`, `@stripe/*` packages or `STRIPE_*` env |
| Supabase | `@supabase/*` packages or `SUPABASE_*` env |
| Clerk | `@clerk/*` packages or `CLERK_*` env |
| Auth0 | `@auth0/*` or `auth0` packages or `AUTH0_*` env |
| Sentry | `@sentry/*` packages or `SENTRY_*` env |
| PostHog | `posthog-js`, `posthog-node` or `POSTHOG_*` env |
| Mixpanel | `mixpanel-browser` or `MIXPANEL_*` env |
| Google Analytics | `react-ga4`, `@next/third-parties`, `GA_MEASUREMENT_*` env |
| Vercel Analytics | `@vercel/analytics`, `@vercel/speed-insights` |
| Cloudflare Analytics | `CLOUDFLARE_ANALYTICS` env |
| OpenAI | `openai` package or `OPENAI_API_KEY` |
| Anthropic | `@anthropic-ai/sdk` or `ANTHROPIC_API_KEY` |
| Resend | `resend` package or `RESEND_API_KEY` |
| SendGrid | `@sendgrid/mail` or `SENDGRID_API_KEY` |

## How to apply this command

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/privacy-docs.py ${ARGS}
```

Then offer:
*"Want to also serve this at https://yourapp.com/privacy? Run `/trust-page` to wire it up with `.well-known/security.txt` and a /security page that links to it."*

🛡  agentic-security · created by Clear Capabilities
