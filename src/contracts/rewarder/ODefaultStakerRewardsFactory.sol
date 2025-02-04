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

pragma solidity 0.8.25;

import {ODefaultStakerRewards} from "./ODefaultStakerRewards.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";
import {Registry} from "@symbioticfi/core/src/contracts/common/Registry.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

contract ODefaultStakerRewardsFactory is Registry, IODefaultStakerRewardsFactory {
    using Clones for address;

    address private immutable STAKER_REWARDS_IMPLEMENTATION;

    constructor(
        address stakerRewardsImplementation
    ) {
        STAKER_REWARDS_IMPLEMENTATION = stakerRewardsImplementation;
    }
    /**
     * @inheritdoc IODefaultStakerRewardsFactory
     */

    function create(
        ODefaultStakerRewards.InitParams calldata params
    ) external returns (address) {
        address stakerRewards =
            STAKER_REWARDS_IMPLEMENTATION.cloneDeterministic(keccak256(abi.encode(totalEntities(), params)));
        ODefaultStakerRewards(stakerRewards).initialize(params);
        _addEntity(stakerRewards);
        return stakerRewards;
    }
}
