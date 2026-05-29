// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MetaTxRelayer {
  function relay(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    // BUG: no nonce, no chainId, no domain separator. Pure ecrecover.
    address signer = ecrecover(hash, v, r, s);
    require(signer != address(0), "bad sig");
    // ...exec on signer's behalf
  }
}
