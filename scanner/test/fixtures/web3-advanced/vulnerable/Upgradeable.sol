// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyVault is Initializable {
  address public owner;
  uint256 public totalDeposits;

  // BUG: no constructor calling _disableInitializers().
  // BUG: no __gap.

  function initialize(address _owner) public initializer {
    owner = _owner;
  }
}
