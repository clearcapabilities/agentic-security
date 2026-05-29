// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTxRelayer {
  mapping(address => uint256) public nonces;
  bytes32 public DOMAIN_SEPARATOR;

  function relay(address user, bytes calldata payload, uint256 nonce, bytes calldata signature) external {
    require(nonce == nonces[user]++, "bad nonce");
    bytes32 hash = keccak256(abi.encode(DOMAIN_SEPARATOR, block.chainid, user, nonce, payload));
    address signer = ECDSA.recover(hash, signature);
    require(signer == user, "bad sig");
  }
}
