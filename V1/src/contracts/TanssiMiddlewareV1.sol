// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract TanssiMiddlewareV1 is OwnableUpgradeable, ReentrancyGuardUpgradeable {
    // Storage gap for upgradeability
    uint256[2000] private __gap;

    function initialize(
        uint64 initialVersion,
        address owner,
        bytes calldata data
    ) external reinitializer(initialVersion) {
        __ReentrancyGuard_init();

        if (owner != address(0)) {
            __Ownable_init(owner);
        }

        _initialize(initialVersion, owner, data);
    }

    function _initialize(uint64, /* initialVersion */ address, /* owner */ bytes memory /* data */ ) internal virtual {}

    function version() external view returns (uint64) {
        return _getInitializedVersion();
    }
}
