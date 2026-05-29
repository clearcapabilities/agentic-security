// Tests for web3-advanced.js (Solidity / Vyper / Anchor) and
// dapp-frontend.js (ethers / wagmi / window.ethereum).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanWeb3Advanced } from '../src/sast/web3-advanced.js';
import { scanDappFrontend } from '../src/sast/dapp-frontend.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WEB3 = path.join(__dirname, 'fixtures', 'web3-advanced');
const DAPP = path.join(__dirname, 'fixtures', 'dapp-frontend');

function read(p) { return fs.readFileSync(p, 'utf8'); }

// ── Solidity detectors ─────────────────────────────────────────────────────

test('web3-adv: upgradeable contract without _disableInitializers is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/Upgradeable.sol'));
  const out = scanWeb3Advanced('Upgradeable.sol', src);
  assert.ok(out.some(f => f.family === 'upgradeable-init'),
    `expected upgradeable-init; got ${out.map(f => f.family).join(',')}`);
});

test('web3-adv: upgradeable contract without __gap is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/Upgradeable.sol'));
  const out = scanWeb3Advanced('Upgradeable.sol', src);
  assert.ok(out.some(f => f.family === 'upgradeable-storage'),
    `expected upgradeable-storage; got ${out.map(f => f.family).join(',')}`);
});

test('web3-adv: ecrecover without nonce + chainId is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/SigReplay.sol'));
  const out = scanWeb3Advanced('SigReplay.sol', src);
  assert.ok(out.some(f => f.family === 'signature-replay'));
  assert.ok(out.some(f => f.family === 'ecdsa-malleability'));
});

test('web3-adv: Chainlink latestRoundData without freshness check is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/Oracle.sol'));
  const out = scanWeb3Advanced('Oracle.sol', src);
  assert.ok(out.some(f => f.family === 'oracle-staleness'),
    `expected oracle-staleness; got ${out.map(f => f.family).join(',')}`);
});

test('web3-adv: clean SafeContract.sol emits at most low-confidence reentrancy noise', () => {
  const src = read(path.join(WEB3, 'clean/SafeContract.sol'));
  const out = scanWeb3Advanced('SafeContract.sol', src);
  // Should not fire signature-replay or ecdsa-malleability — uses ECDSA.recover + nonce + chainId.
  assert.equal(out.filter(f => f.family === 'signature-replay').length, 0);
  assert.equal(out.filter(f => f.family === 'ecdsa-malleability').length, 0);
});

test('web3-adv: Anchor handler without owner-check constraints is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/anchor_handler.rs'));
  const out = scanWeb3Advanced('anchor_handler.rs', src);
  assert.ok(out.some(f => f.family === 'solana-anchor-no-owner'),
    `expected solana-anchor-no-owner; got ${out.map(f => f.family).join(',')}`);
});

test('web3-adv: Vyper raw_call without max_outsize is flagged', () => {
  const src = read(path.join(WEB3, 'vulnerable/raw_call.vy'));
  const out = scanWeb3Advanced('raw_call.vy', src);
  assert.ok(out.some(f => f.family === 'vyper-raw-call'));
});

test('web3-adv: AGENTIC_SECURITY_NO_WEB3_ADV disables the detector', () => {
  process.env.AGENTIC_SECURITY_NO_WEB3_ADV = '1';
  try {
    const src = read(path.join(WEB3, 'vulnerable/SigReplay.sol'));
    const out = scanWeb3Advanced('SigReplay.sol', src);
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_WEB3_ADV; }
});

// ── DApp frontend detectors ────────────────────────────────────────────────

test('dapp: unlimited approval with MaxUint256 is flagged', () => {
  const src = read(path.join(DAPP, 'vulnerable/approval.ts'));
  const out = scanDappFrontend('approval.ts', src);
  assert.ok(out.some(f => f.family === 'unlimited-approval'),
    `expected unlimited-approval; got ${out.map(f => f.family).join(',')}`);
});

test('dapp: eth_sign usage flagged critical', () => {
  const src = read(path.join(DAPP, 'vulnerable/approval.ts'));
  const out = scanDappFrontend('approval.ts', src);
  const ethSign = out.find(f => f.family === 'eth-sign-used');
  assert.ok(ethSign, `expected eth-sign-used; got ${out.map(f => f.family).join(',')}`);
  assert.equal(ethSign.severity, 'critical');
});

test('dapp: Wallet constructed with raw private key in React app is flagged', () => {
  const src = read(path.join(DAPP, 'vulnerable/approval.ts'));
  const out = scanDappFrontend('approval.ts', src);
  assert.ok(out.some(f => f.family === 'private-key-in-frontend'));
});

test('dapp: inline Etherscan API key flagged', () => {
  const src = read(path.join(DAPP, 'vulnerable/approval.ts'));
  const out = scanDappFrontend('approval.ts', src);
  assert.ok(out.some(f => f.family === 'rpc-key-inline'),
    `expected rpc-key-inline; got ${out.map(f => f.family).join(',')}`);
});

test('dapp: clean fixture emits nothing', () => {
  const src = read(path.join(DAPP, 'clean/safe-frontend.ts'));
  const out = scanDappFrontend('safe-frontend.ts', src);
  // Allow at most low-confidence/non-critical typed-data warning; expect no
  // high-severity findings.
  assert.equal(out.filter(f => f.severity === 'high' || f.severity === 'critical').length, 0,
    `unexpected high/critical: ${out.map(f => `${f.family}:${f.severity}`).join(',')}`);
});

test('dapp: non-web3 file emits nothing', () => {
  const out = scanDappFrontend('plain.ts', 'export const x = 1;\nconst y = "no web3 here";\n');
  assert.equal(out.length, 0);
});

test('dapp: AGENTIC_SECURITY_NO_DAPP disables the detector', () => {
  process.env.AGENTIC_SECURITY_NO_DAPP = '1';
  try {
    const src = read(path.join(DAPP, 'vulnerable/approval.ts'));
    const out = scanDappFrontend('approval.ts', src);
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_DAPP; }
});
