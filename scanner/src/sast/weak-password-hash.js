// Weak password hashing detector.
//
// Context-gated: only fires when the hash input variable is named
// password/secret/credential or the enclosing function is password-related.
// Detects MD5/SHA1 without salt for password storage.

const PASSWORD_CONTEXT = /\b(password|passwd|pwd|secret|credential|passphrase|pass_hash|user_pass)\b/i;
const PASSWORD_FUNC = /\b(hashPassword|encryptPassword|checkPassword|verifyPassword|createHash|setPassword|validatePassword|hash_password|check_password)\b/i;

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }

const PATTERNS = {
  js: {
    ext: /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i,
    rules: [
      { re: /\bcreateHash\s*\(\s*['"](?:md5|sha1|sha-1|md4)['"]\s*\)[\s\S]{0,60}\.update\s*\(\s*(\w+)/g, label: 'createHash with weak algorithm' },
      { re: /\bmd5\s*\(\s*(\w+)/g, label: 'md5() function call' },
      { re: /\bsha1\s*\(\s*(\w+)/g, label: 'sha1() function call' },
    ],
  },
  py: {
    ext: /\.py$/i,
    rules: [
      { re: /\bhashlib\.(?:md5|sha1)\s*\(\s*(\w+)/g, label: 'hashlib.md5/sha1' },
      { re: /\bhashlib\.new\s*\(\s*['"](?:md5|sha1)['"]\s*\)[\s\S]{0,40}\.update\s*\(\s*(\w+)/g, label: 'hashlib.new with weak algorithm' },
    ],
  },
  go: {
    ext: /\.go$/i,
    rules: [
      { re: /\bmd5\.(?:Sum|New)\s*\(\s*(?:\[\]byte\s*\(\s*)?(\w+)/g, label: 'md5.Sum/New' },
      { re: /\bsha1\.(?:Sum|New)\s*\(\s*(?:\[\]byte\s*\(\s*)?(\w+)/g, label: 'sha1.Sum/New' },
    ],
  },
  ruby: {
    ext: /\.rb$/i,
    rules: [
      { re: /\bDigest::(?:MD5|SHA1)\s*\.\s*(?:hexdigest|digest|base64digest)\s*\(\s*(\w+)/g, label: 'Digest::MD5/SHA1' },
      { re: /\b(?:Digest::)?(?:MD5|SHA1)\.new[\s\S]{0,40}\.update\s*\(\s*(\w+)/g, label: 'Digest MD5/SHA1 new+update' },
    ],
  },
  csharp: {
    ext: /\.cs$/i,
    rules: [
      // MD5.Create()…ComputeHash(<var>) / MD5.HashData(<var>) — capture hashed var.
      { re: /\b(?:MD5|SHA1)\s*\.\s*(?:Create\s*\(\s*\)\s*\.\s*ComputeHash|HashData)\s*\([\s\S]{0,120}?(\w+)\s*\)/g, label: 'MD5/SHA1 ComputeHash/HashData' },
      { re: /\bnew\s+(?:MD5|SHA1)(?:CryptoServiceProvider|Managed)?\s*\(/g, label: 'MD5/SHA1 provider' },
    ],
  },
  kotlin: {
    ext: /\.kt$/i,
    rules: [
      { re: /\bMessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)[\s\S]{0,80}?\.digest\s*\(\s*(\w+)/g, label: 'MessageDigest MD5/SHA-1' },
    ],
  },
  php: {
    ext: /\.(?:php|phtml)$/i,
    rules: [
      { re: /\b(?:md5|sha1)\s*\(\s*\$?(\w+)/g, label: 'md5()/sha1()' },
      { re: /\bhash\s*\(\s*['"](?:md5|sha1)['"]\s*,\s*\$?(\w+)/g, label: 'hash("md5"/"sha1", …)' },
    ],
  },
};

export function scanWeakPasswordHash(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];

  const findings = [];
  let lang = null;
  for (const v of Object.values(PATTERNS)) {
    if (v.ext.test(fp)) { lang = v; break; }
  }
  if (!lang) return [];

  for (const { re, label } of lang.rules) {
    re.lastIndex = 0;
    for (const m of raw.matchAll(re)) {
      const inputVar = m[1] || '';
      const line = _line(raw, m.index);
      // Check context: password-named variable or password-related function
      const funcStart = raw.lastIndexOf('\n', Math.max(0, m.index - 500));
      const context = raw.slice(funcStart, m.index + m[0].length + 100);
      if (!PASSWORD_CONTEXT.test(inputVar) && !PASSWORD_CONTEXT.test(context) && !PASSWORD_FUNC.test(context)) continue;
      // Check for salt within 10 lines before
      const before = raw.slice(Math.max(0, m.index - 400), m.index);
      const hasSalt = /\b(salt|randomBytes|urandom|os\.urandom|crypto\.randomBytes|bcrypt|argon2|scrypt|pbkdf2)\b/i.test(before);
      if (hasSalt) continue;

      findings.push({
        id: `weak-pw-hash:${fp}:${line}`,
        file: fp, line,
        vuln: `Weak Password Hashing — ${label} for password without salt`,
        severity: 'critical',
        family: 'weak-password-hash',
        cwe: 'CWE-916',
        parser: 'WEAK-PW-HASH',
        confidence: 0.80,
        description: `${label} used on a password-context variable without salt. MD5/SHA1 are fast hashes trivially reversed via rainbow tables. Unsalted hashes are cracked in seconds.`,
        remediation: 'Use bcrypt (cost ≥ 12), argon2id, or scrypt. Never use MD5/SHA1/SHA256 for password storage.',
      });
    }
  }
  return findings;
}
