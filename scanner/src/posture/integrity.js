// Tamper-evidence for `.agentic-security/last-scan.json`.
//
// Writes a sibling `.sig` file containing an HMAC-SHA256 of the JSON body.
// Readers verify the signature before trusting findings counts / file paths.
//
// KEY MATERIAL (premortem #1):
//   The key is read from one of:
//     1. $AGENTIC_SECURITY_HMAC_KEY  — explicit operator-provided key (hex)
//     2. $XDG_CONFIG_HOME/agentic-security/scan-key  (or ~/.config/agentic-security/scan-key)
//        — a per-install 32-byte random key, mode 0600, generated on first use.
//   The old hostname-derived key is accepted in VERIFY-ONLY mode for one
//   release so existing signed `last-scan.json` files keep verifying. New
//   signatures only use the random key.
//
// Threat model: this is a guardrail against accidental corruption, naive
// manual edits, CI-cache poisoning, and supply-chain planting of a fake
// last-scan.json designed to weaponize MCP `apply_fix`. An attacker who
// reads $AGENTIC_SECURITY_HMAC_KEY or the on-disk key file can forge — so
// the key file is mode 0600, and the env-var variant is intended for
// operators who manage secrets separately (Doppler/Infisical/etc.).

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const _HMAC_SALT = 'agentic-security:last-scan:v1';

function _keyDir() {
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg && xdg.length ? xdg : path.join(os.homedir(), '.config');
  return path.join(base, 'agentic-security');
}
function _keyPath() { return path.join(_keyDir(), 'scan-key'); }

function _readOrGenerateKey() {
  const fromEnv = process.env.AGENTIC_SECURITY_HMAC_KEY;
  if (fromEnv && /^[0-9a-fA-F]{32,}$/.test(fromEnv.trim())) {
    return Buffer.from(fromEnv.trim(), 'hex');
  }
  const fp = _keyPath();
  try {
    if (fs.existsSync(fp)) {
      const hex = fs.readFileSync(fp, 'utf8').trim();
      if (/^[0-9a-fA-F]{32,}$/.test(hex)) return Buffer.from(hex, 'hex');
    }
  } catch { /* fall through to generate */ }
  // Generate, mode 0600.
  const buf = crypto.randomBytes(32);
  try {
    fs.mkdirSync(_keyDir(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(fp, buf.toString('hex') + '\n', { mode: 0o600 });
  } catch { /* best-effort — fall back to in-memory key for the process */ }
  return buf;
}

function _legacyHostnameKey() {
  return crypto.createHash('sha256').update(`${_HMAC_SALT}:${os.hostname()}`).digest();
}

let _cachedKey = null;
function _key() {
  if (_cachedKey) return _cachedKey;
  _cachedKey = _readOrGenerateKey();
  return _cachedKey;
}

export function signLastScan(body) {
  return crypto.createHmac('sha256', _key()).update(body).digest('hex');
}

// Verify body against a sibling .sig file.
// Returns true if valid under the current install key OR the legacy hostname
// key (for one-release migration), false if invalid, null if sig file is
// absent (first-run case — call sites decide whether absent == fail-closed).
export function verifyLastScan(body, sigFile) {
  if (!fs.existsSync(sigFile)) return null;
  let stored;
  try { stored = fs.readFileSync(sigFile, 'utf8').trim(); }
  catch { return false; }
  const tryKey = (k) => {
    try {
      const expected = crypto.createHmac('sha256', k).update(body).digest('hex');
      if (stored.length !== expected.length) return false;
      return crypto.timingSafeEqual(Buffer.from(stored, 'hex'), Buffer.from(expected, 'hex'));
    } catch { return false; }
  };
  if (tryKey(_key())) return true;
  // Legacy hostname-key path — accepted for verification only, not for new
  // signatures. Remove after one minor release.
  if (tryKey(_legacyHostnameKey())) return true;
  return false;
}

// Test-only helpers (premortem-tracked):
export function _resetKeyCacheForTests() { _cachedKey = null; }
export function _keyFilePathForTests() { return _keyPath(); }
