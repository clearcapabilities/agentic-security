import { ethers, Wallet } from "ethers";

// React App component (web3 frontend).
export async function unsafeApprove(token: any, spender: string) {
  // BUG: unlimited approval to a spender contract.
  await token.approve(spender, ethers.constants.MaxUint256);
}

export async function deathSign(provider: any) {
  // BUG: eth_sign signs an arbitrary 32-byte hash.
  return provider.request({ method: 'eth_sign', params: ['0xabc', '0xdef'] });
}

// BUG: private key literal in client bundle (React app).
const wallet = new Wallet("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

// BUG: Etherscan API key inline.
const url = `https://api.etherscan.io/api?module=account&action=balance&apikey=ABCD1234567890ABCDEF1234567890ABCDEF12`;
