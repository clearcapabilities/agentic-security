// Webhook signature verification audit.
//
// Every major webhook provider (Stripe, GitHub, Clerk, Svix, Resend, Twilio)
// requires callers to verify the request signature before processing the
// payload. Skipping verification means anyone who discovers your webhook URL
// can trigger real business logic (fake payments, fake user events, fake
// deploys) with zero authentication.
//
// F1 safety: rules fire only when ALL of:
//   1. The file path or a route string contains "webhook" or provider name
//   2. The file reads req.body or payload from request
//   3. NO recognised verification call is present in the file
//
// Benchmark apps (NodeGoat, Juice Shop) predate webhook patterns; this rule
// produces no findings on them.

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;

// File-path signals: the file is a webhook handler
const WEBHOOK_FILE_RE = /(?:^|\/)(?:webhook|webhooks|wh|hook|hooks)[\w.-]*\.[cm]?[jt]sx?$/i;
// Route string signals within file content
const WEBHOOK_ROUTE_RE = /(?:router|app|server)\s*\.\s*(?:post|all)\s*\(\s*['"`][^'"`]*webhook[^'"`]*['"`]/i;
// Next.js route file in a webhook directory/segment
const NEXT_WEBHOOK_RE = /(?:^|\/)(?:app|pages)\/(?:api\/)?[^/]*webhook[^/]*\/(?:route|index)\.[cm]?[jt]sx?$/i;

// Provider-specific verification calls
const STRIPE_VERIFY_RE = /(?:stripe|Stripe)\s*\.\s*webhooks?\s*\.\s*constructEvent/;
const GITHUB_VERIFY_RE = /(?:X-Hub-Signature|x-hub-signature|createHmac|timingSafeEqual)[^;]{0,200}(?:sha256|sha1)/i;
const SVIX_VERIFY_RE = /(?:new\s+Webhook|wh\.verify|Svix|svix)/;
const CLERK_VERIFY_RE = /(?:verifyWebhook|clerkClient\.verifyToken|Webhook\s*\()/;
const RESEND_VERIFY_RE = /(?:Resend\.verifyWebhookSignature|resend\.webhooks\.verify)/i;
const TWILIO_VERIFY_RE = /(?:twilio\.validateRequest|validateExpressRequest|validateWebhook)/i;
const GENERIC_SIG_VERIFY_RE = /(?:signature|sig)\s*[!=]{2,3}|timingSafeEqual|hmac\.digest|verifySignature|validateSignature|webhookSecret|WEBHOOK_SECRET/i;

// Request body consumed (confirms it's a handler, not a type def)
const BODY_READ_RE = /(?:req|request)\s*\.\s*(?:body|rawBody|text\(\)|json\(\))|await\s+(?:req|request)\.(?:text|json)\s*\(/;

function _isVerified(content) {
  return STRIPE_VERIFY_RE.test(content) ||
    GITHUB_VERIFY_RE.test(content) ||
    SVIX_VERIFY_RE.test(content) ||
    CLERK_VERIFY_RE.test(content) ||
    RESEND_VERIFY_RE.test(content) ||
    TWILIO_VERIFY_RE.test(content) ||
    GENERIC_SIG_VERIFY_RE.test(content);
}

function scanWebhook(file, content) {
  if (!_SCAN_EXT_RE.test(file)) return [];
  if (_NONPROD_RE.test(file)) return [];

  // Gate 1: is this actually a webhook handler file?
  const isWebhookFile = WEBHOOK_FILE_RE.test(file) || NEXT_WEBHOOK_RE.test(file);
  const hasWebhookRoute = WEBHOOK_ROUTE_RE.test(content);
  if (!isWebhookFile && !hasWebhookRoute) return [];

  // Gate 2: does it read the request body (confirms it's a handler, not a util)?
  if (!BODY_READ_RE.test(content)) return [];

  // Gate 3: no verification present → finding
  if (_isVerified(content)) return [];

  // Detect which provider(s) are referenced to give a precise title
  const providers = [];
  if (/stripe/i.test(content)) providers.push('Stripe');
  if (/github/i.test(content)) providers.push('GitHub');
  if (/svix/i.test(content)) providers.push('Svix');
  if (/clerk/i.test(content)) providers.push('Clerk');
  if (/resend/i.test(content)) providers.push('Resend');
  if (/twilio/i.test(content)) providers.push('Twilio');
  const providerStr = providers.length ? providers.join('/') + ' ' : '';

  // Find the line of the first body read or route definition
  const lines = content.split('\n');
  const triggerLine = lines.findIndex(l => BODY_READ_RE.test(l) || WEBHOOK_ROUTE_RE.test(l));
  const lineNum = triggerLine >= 0 ? triggerLine + 1 : 1;

  const providerRemediations = {
    'Stripe': 'const event = stripe.webhooks.constructEvent(rawBody, req.headers[\'stripe-signature\'], process.env.STRIPE_WEBHOOK_SECRET);',
    'GitHub': 'Use crypto.timingSafeEqual to compare HMAC-SHA256 of the raw body against the X-Hub-Signature-256 header.',
    'Svix': 'const wh = new Webhook(process.env.WEBHOOK_SECRET); wh.verify(payload, headers);',
    'Clerk': 'const evt = await clerkClient.verifyWebhook(req);',
  };
  const fixSnippet = providers.length
    ? providerRemediations[providers[0]] || 'Verify the provider-specific HMAC signature before processing the payload.'
    : 'Verify the HMAC signature from the webhook provider before processing any payload data.';

  return [{
    id: `webhook:MISSING_SIGNATURE_VERIFY:${file}:${lineNum}`,
    title: `${providerStr}Webhook handler missing signature verification`,
    severity: 'high',
    file, line: lineNum,
    vuln: 'Webhook — Missing Signature Verification',
    description: `This webhook handler reads the request body without verifying the ${providerStr}signature header. Anyone who discovers the endpoint URL can POST arbitrary payloads and trigger real business logic — fake Stripe payments marked as successful, fake GitHub events triggering deploys, fake user creation events.`,
    remediation: fixSnippet + '\n\nIMPORTANT: you must pass the raw (un-parsed) request body to the signature verifier, not the parsed JSON object.',
    cwe: 'CWE-345',
  }];
}

export { scanWebhook };
