import { ethers } from "ethers";

// React App. Exact-amount approval; no eth_sign; no private key in frontend.
export async function safeApprove(token: any, spender: string, amount: bigint) {
  await token.approve(spender, amount);
}

export async function signTransfer(signer: any, domain: any, types: any, value: any) {
  // EIP-712 typed data signing with chainId in domain.
  return signer.signTypedData({ ...domain, chainId: 1 }, types, value);
}
