// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "../../src/contracts/TanssiMiddlewareV1.sol";

contract TanssiMiddlewareV2Mock is TanssiMiddlewareV1 {
    // New storage slot
    uint256 public newValue;

    // Updated storage gap for upgradeability
    // Reduced by 1 to account for the new uint256 storage slot
    uint256[1999] private __gap;

    // New feature added in V2
    function newFeature() external pure returns (string memory) {
        return "New Feature Activated";
    }

    function _initialize(
        uint64 /* initialVersion */,
        address /* owner */,
        bytes memory data
    ) internal virtual override {
        if (data.length >= 32) {
            // Extract the first uint256 from the data
            uint256 value;
            assembly {
                value := mload(add(data, 32))
            }
            newValue = value;
        }
    }

    // New data value added in V2
    function getNewValue() external view returns (uint256) {
        return newValue;
    }
}