// SPDX-License-Identifier: GPL-3.0-or-later
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

pragma solidity ^0.8.0;

import {IODefaultStakerRewards} from "./IODefaultStakerRewards.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";

interface IODefaultStakerRewardsFactory is IRegistry {
    error ODefaultStakerRewardsFactory__AlreadySet();
    error ODefaultStakerRewardsFactory__InvalidAddress();
    error ODefaultStakerRewardsFactory__InvalidImplementation();
    error ODefaultStakerRewardsFactory__InvalidVersion();
    error ODefaultStakerRewardsFactory__NotVault();

    /**
     * @notice Emitted when a new implementation is set.
     * @param implementation address of the new implementation
     */
    event SetImplementation(address indexed implementation);

    /**
     * @notice Get the current implementation of the staker rewards contract.
     * @return address of the implementation
     */
    function getImplementation() external view returns (address);

    /**
     * @notice Set a new implementation for staker rewards contract.
     * @param implementation address of the new implementation
     */
    function setImplementation(
        address implementation
    ) external;

    /**
     * @notice Create a default staker rewards contract for a given vault.
     * @param sharedVault address of the shared vault
     * @param params initial parameters needed for a staker rewards contract deployment
     * @return address of the created staker rewards contract
     */
    function create(
        address sharedVault,
        IODefaultStakerRewards.InitParams calldata params
    ) external returns (address);
}
