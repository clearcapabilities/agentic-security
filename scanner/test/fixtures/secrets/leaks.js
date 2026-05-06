// Test fixture for secret detection.
// IMPORTANT: literal-format provider secrets (Stripe / AWS / GitHub PAT) are intentionally NOT stored here
// to avoid GitHub Push Protection blocks. Named-pattern detection is exercised in smoke.test.js
// via runtime-constructed temp fixtures. This file covers the entropy / hardcoded-credential paths.

// High-entropy literal — should trip the entropy scanner
const sessionSecret = "Q7eX2p9mZ4kR8nV6tH3sL1wU5yJ0aB";

// Hardcoded password — should trip the credential-name heuristic
const password = "hunter2hunter2hunter";

// Hardcoded API key — should trip the credential-name heuristic
const apiKey = "abc123abc123abc123abc123";

// PEM private-key marker (truncated) — should trip the private-key pattern
// pem-marker:[BEGIN_RSA_KEY]

// Note: a real Stripe-pattern test runs at smoke.test.js execution time using a tmp dir.
