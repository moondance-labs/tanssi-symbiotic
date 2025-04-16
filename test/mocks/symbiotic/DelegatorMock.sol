//SPDX-License-Identifier: GPL-3.0-or-later

// Copyright (C) Moondance Labs Ltd.
// This file is part of Tanssi.
// Tanssi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// Tanssi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with Tanssi.  If not, see <http://www.gnu.org/licenses/>
pragma solidity 0.8.25;

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
        bytes32, /*subnetwork*/
        address operator,
        uint48, /*timestamp*/
        bytes memory hints
    ) internal view override returns (uint256, bytes memory) {
        uint256 operatorStake = IVault(vault).activeBalanceOf(operator);
        return (hints.length != 0 ? (0, bytes("0xrandomData")) : (operatorStake, bytes("")));
    }
}
