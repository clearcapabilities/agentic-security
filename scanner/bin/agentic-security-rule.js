#!/usr/bin/env node
// agentic-security-rule — CLI for signing / verifying custom rule packs.
//
// Subcommands:
//   keygen                Generate an Ed25519 key pair (PRIVATE KEY printed
//                         to stdout; handle with care).
//   sign <rule-yml>       Sign the rule file. Writes <rule-yml>.sig.
//                         Reads the private key from $AGENTIC_SECURITY_PRIVATE_KEY
//                         or --key <base64>.
//   verify <rule-yml>     Verify against the project's trusted-keys.json
//                         (or bundled official keys). Honors revocation.
//
// First-time setup walkthrough:
//
//   1) Generate a key pair:
//        agentic-security-rule keygen > .agentic-security/MY_KEY.json
//        (review the file. KEEP the private key SECRET — do not commit it.)
//
//   2) Add the public key to .agentic-security/trusted-keys.json:
//        {
//          "keys": [
//            { "id": "my-team-2026", "alg": "ed25519",
//              "publicKey": "<paste publicKey from step 1>" }
//          ]
//        }
//
//   3) Tell the scanner to trust project-local keys (audit-logged):
//        export AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1
//
//   4) Author a custom rule at .agentic-security/rules/my-rule.yml.
//
//   5) Sign it:
//        export AGENTIC_SECURITY_PRIVATE_KEY="<paste privateKey from step 1>"
//        agentic-security-rule sign .agentic-security/rules/my-rule.yml
//
//   6) Verify before commit:
//        agentic-security-rule verify .agentic-security/rules/my-rule.yml
//
// CAUTION: the private key in step 1 is a SECRET. Anyone with it can sign
// rules that will execute in your CI. Store in a password manager / KMS,
// never in source control or shell history. Use --rotate to retire keys.

import { keygen, signRulePack, verifyRulePack, loadTrustedKeys } from '../src/posture/rule-pack-signing.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const cmd = process.argv[2];
const args = process.argv.slice(3);

function die(msg, code = 1) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

function pickArg(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : null;
}

if (cmd === 'keygen') {
  const kp = keygen();
  const out = {
    note: 'STORE THE privateKey SECURELY. Do not commit it to source control. Anyone with this key can sign rules that execute in your CI.',
    id: `key-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`,
    alg: 'ed25519',
    issuedAt: new Date().toISOString(),
    publicKey:  kp.publicKey,
    privateKey: kp.privateKey,
  };
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.stderr.write('\nagentic-security-rule: keypair generated.\n');
  process.stderr.write('  · Add publicKey to .agentic-security/trusted-keys.json\n');
  process.stderr.write('  · Store privateKey in a password manager / KMS\n');
  process.stderr.write('  · Set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1 so the scanner trusts project-local keys\n');
  process.exit(0);
}

if (cmd === 'sign') {
  const target = args.find(a => !a.startsWith('--'));
  if (!target) die('Usage: agentic-security-rule sign <rule-yml> [--key <base64>]');
  if (!fs.existsSync(target)) die(`File not found: ${target}`);
  const key = pickArg('--key') || process.env.AGENTIC_SECURITY_PRIVATE_KEY;
  if (!key) die('No private key. Set AGENTIC_SECURITY_PRIVATE_KEY or pass --key <base64>.');
  try {
    signRulePack(target, key);
    process.stdout.write(`Signed: ${target}.sig\n`);
    process.exit(0);
  } catch (e) {
    die(`Sign failed: ${e.message}`);
  }
}

if (cmd === 'verify') {
  const target = args.find(a => !a.startsWith('--'));
  if (!target) die('Usage: agentic-security-rule verify <rule-yml>');
  if (!fs.existsSync(target)) die(`File not found: ${target}`);
  const scanRoot = path.resolve('.');
  const keys = loadTrustedKeys(scanRoot);
  if (keys.length === 0) {
    process.stderr.write('agentic-security-rule: no trusted keys configured.\n');
    process.stderr.write('  Add keys to .agentic-security/trusted-keys.json and set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1.\n');
    process.exit(2);
  }
  const r = verifyRulePack(target, keys);
  if (r.ok) {
    process.stdout.write(`OK — signed by ${r.keyId}\n`);
    process.exit(0);
  } else {
    process.stderr.write(`FAILED: ${r.reason}${r.keyId ? ` (key ${r.keyId})` : ''}\n`);
    process.exit(1);
  }
}

die(`Usage: agentic-security-rule <keygen | sign <rule.yml> | verify <rule.yml>>`);
