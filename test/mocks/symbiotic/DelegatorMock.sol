// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {console2} from "forge-std/console2.sol";
import {BaseDelegator} from "@symbiotic/contracts/delegator/BaseDelegator.sol";
import {Entity} from "@symbiotic/contracts/common/Entity.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

contract DelegatorMock is BaseDelegator {
    constructor(
        address networkRegistry,
        address vaultFactory,
        address operatorVaultOptInService,
        address operatorNetworkOptInService,
        address delegatorFactory,
        uint64 entityType
    )
        BaseDelegator(
            networkRegistry,
            vaultFactory,
            operatorVaultOptInService,
            operatorNetworkOptInService,
            delegatorFactory,
            entityType
        )
    {}

    function _stakeAt(
        bytes32 subnetwork,
        address operator,
        uint48 timestamp,
        bytes memory hints
    ) internal view override returns (uint256, bytes memory) {
        uint256 operatorStake = IVault(vault).activeBalanceOf(operator);
        return (hints.length > 0 ? (0, bytes("0xrandomData")) : (operatorStake, bytes("")));
    }
}
