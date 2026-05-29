// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregator {
  function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract LendingMarket {
  IAggregator public ethUsdFeed;

  function getCollateralUsd(uint256 ethAmount) external view returns (uint256) {
    // BUG: no staleness check on updatedAt.
    (, int256 price,,,) = ethUsdFeed.latestRoundData();
    return ethAmount * uint256(price) / 1e8;
  }
}
