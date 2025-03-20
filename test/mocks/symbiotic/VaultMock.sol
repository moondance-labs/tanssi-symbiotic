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

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {VaultStorage} from "@symbiotic/contracts/vault/VaultStorage.sol";
import {IVaultStorage} from "@symbiotic/interfaces/vault/IVaultStorage.sol";
import {MigratableEntity} from "@symbiotic/contracts/common/MigratableEntity.sol";

import {Entity} from "@symbiotic/contracts/common/Entity.sol";

contract VaultMock is VaultStorage, MigratableEntity, IVault {
    uint256 public totalAtStake;

    mapping(address => uint256) public operatorStake;
    address[] public operators;

    constructor(
        address delegatorFactory,
        address slasherFactory,
        address vaultFactory,
        address _collateral
    ) VaultStorage(delegatorFactory, slasherFactory) MigratableEntity(vaultFactory) {
        collateral = _collateral;
        epochDuration = 10 days;
    }

    function test() public {}

    function isInitialized() external pure returns (bool) {
        return true;
    }

    function totalStake() external view returns (uint256) {}

    function activeBalanceOfAt(
        address account,
        uint48, /*timestamp*/
        bytes calldata /*hints*/
    ) external view returns (uint256) {
        return operatorStake[account];
    }

    function activeBalanceOf(
        address account
    ) external view returns (uint256) {
        return operatorStake[account];
    }

    function withdrawalsOf(uint256 epoch, address account) external view returns (uint256) {}

    function slashableBalanceOf(
        address account
    ) external view returns (uint256) {}

    function deposit(
        address onBehalfOf,
        uint256 amount
    ) external returns (uint256 depositedAmount, uint256 mintedShares) {
        operatorStake[onBehalfOf] += amount;
        operators.push(onBehalfOf);
        totalAtStake += amount;
        depositedAmount = amount;
        mintedShares = amount;
    }

    function withdraw(address claimer, uint256 amount) external returns (uint256 burnedShares, uint256 mintedShares) {}

    function redeem(address claimer, uint256 shares) external returns (uint256 withdrawnAssets, uint256 mintedShares) {}

    function claim(address recipient, uint256 epoch) external returns (uint256 amount) {}

    function claimBatch(address recipient, uint256[] calldata epochs) external returns (uint256 amount) {}

    function onSlash(uint256 amount, uint48 /*captureTimestamp */ ) external returns (uint256 slashedAmount) {
        totalAtStake -= amount;
        slashedAmount = amount;
        for (uint256 i = 0; i < operators.length; i++) {
            if (operatorStake[operators[i]] >= amount) {
                operatorStake[operators[i]] -= amount;
                break;
            }
        }
    }

    function setDepositWhitelist(
        bool status
    ) external {}

    function setDepositorWhitelistStatus(address account, bool status) external {}

    function setIsDepositLimit(
        bool status
    ) external {}

    function setDepositLimit(
        uint256 limit
    ) external {}

    function setDelegator(
        address delegator_
    ) external nonReentrant {
        delegator = delegator_;

        isDelegatorInitialized = true;

        emit SetDelegator(delegator_);
    }

    function setSlasher(
        address slasher_
    ) external nonReentrant {
        isSlasherInitialized = true;
        slasher = slasher_;
        emit SetSlasher(slasher_);
    }
}
