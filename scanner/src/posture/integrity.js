// Tamper-evidence for `.agentic-security/last-scan.json`.
//
// Writes a sibling `.sig` file containing an HMAC-SHA256 of the JSON body.
// Readers verify the signature before trusting findings counts / file paths.
// Not a cryptographic guarantee against an attacker with filesystem access
// (they can re-sign), but blocks accidental corruption, naive manual edits,
// CI cache poisoning, and supply-chain planting of a fake last-scan.json
// designed to weaponize `apply_fix`.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';

const _HMAC_SALT = 'agentic-security:last-scan:v1';

function _key() {
  return crypto.createHash('sha256').update(`${_HMAC_SALT}:${os.hostname()}`).digest();
}

export function signLastScan(body) {
  return crypto.createHmac('sha256', _key()).update(body).digest('hex');
}

// Verify body against a sibling .sig file.
// Returns true if valid, false if invalid, null if sig file is absent
// (first-run case — call sites decide whether absent == fail-closed).
export function verifyLastScan(body, sigFile) {
  if (!fs.existsSync(sigFile)) return null;
  try {
    const stored = fs.readFileSync(sigFile, 'utf8').trim();
    const expected = signLastScan(body);
    if (stored.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(stored, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}
