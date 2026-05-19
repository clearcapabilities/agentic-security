// Cross-language chain metadata (FR-CHAIN-FILTER + FR-FAMILY-REGISTRY).
//
// Phase-1 polyglot bench revealed two issues with the cross-language chain
// detectors:
//
//   1. Chains fired on ANY high-severity finding in the linked file. That
//      included CSRF, header-hardening, body-parser DoS — incidental issues
//      that have nothing to do with what flows across the language boundary.
//      The chain was semantically wrong.
//
//   2. Chain findings got auto-slugged family names like
//      `cross-language-taint-client-call-post-us` (truncated to 40 chars).
//      Ugly, brittle, and useless for filtering downstream.
//
// Both fixed here. The cross-lang-* modules import these helpers; the
// helpers are tested in isolation so the contract is auditable.

// ─── FR-CHAIN-FILTER ────────────────────────────────────────────────────────
//
// Only emit a cross-language chain when the linked finding is in a family
// that propagates meaningfully across a service boundary. CSRF on the OTHER
// side of a queue tells you nothing useful; SQL injection does.

const CHAIN_WORTHY_FAMILIES = new Set([
  'sql-injection',
  'command-injection',
  'xss',
  'ssrf',
  'code-injection',
  'insecure-deserialization',
  'xxe',
  'path-traversal',
  'jndi-injection',
  'ldap-injection',
  'xpath-injection',
  'nosql-injection',
  'ssti',
  'idor',                // ownership flows across language boundary
  'mass-assignment',     // request-body taint flows
  'prototype-pollution', // pollution flows through JSON
]);

// Substring patterns we'll treat as chain-worthy when finding.family is not set.
// Lets callers (especially unit tests) pass minimal finding objects without
// requiring the dedupe pipeline to have stamped family first.
const CHAIN_WORTHY_VULN_PATTERNS = [
  /\bSQL Injection\b/i, /\bCommand Injection\b/i, /\bXSS\b/i, /\bSSRF\b/i,
  /\bCode Injection\b/i, /\bDeserialization\b/i, /\bXXE\b/i,
  /\bPath Traversal\b/i, /\bJNDI\b/i, /\bLDAP Injection\b/i,
  /\bXPath Injection\b/i, /\bNoSQL Injection\b/i, /\bSSTI\b/i,
  /\bIDOR\b/i, /\bMass Assignment\b/i, /\bPrototype Pollution\b/i,
];

/**
 * Is this finding eligible to be the "tail" of a cross-language chain?
 * Returns true only for families whose taint genuinely propagates across
 * a service boundary. Falls back to a vuln-string substring check when
 * the finding object has no `family` field yet.
 */
export function isChainWorthy(finding) {
  if (!finding || typeof finding !== 'object') return false;
  const fam = finding.family;
  if (fam) return CHAIN_WORTHY_FAMILIES.has(fam);
  const vuln = finding.vuln;
  if (typeof vuln !== 'string') return false;
  return CHAIN_WORTHY_VULN_PATTERNS.some(re => re.test(vuln));
}

/**
 * Filter a list of high-severity findings down to the chain-worthy ones.
 */
export function chainWorthyFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.filter(isChainWorthy);
}

// ─── FR-FAMILY-REGISTRY ─────────────────────────────────────────────────────
//
// Each cross-language detector has a canonical family name. Reports filter
// by these stable strings instead of an auto-slug of the chain's vuln text.

export const XLANG_FAMILIES = Object.freeze({
  openapi: 'xlang-openapi',
  grpc:    'xlang-grpc',
  graphql: 'xlang-graphql',
  queue:   'xlang-queue',
  orm:     'xlang-orm',
  iac:     'xlang-iac',
});

/**
 * Resolve the canonical family for a cross-language chain by the boundary
 * type that produced it. Detectors call this when emitting chain findings.
 */
export function familyForBoundary(boundary) {
  if (typeof boundary !== 'string') return 'xlang-unknown';
  return XLANG_FAMILIES[boundary] || 'xlang-unknown';
}

// For tests + the no-dead-modules check.
export const _internals = { CHAIN_WORTHY_FAMILIES };
