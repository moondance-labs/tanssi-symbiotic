// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {ODefaultStakerRewards} from "./ODefaultStakerRewards.sol";

import {IODefaultStakerRewardsFactory} from "../../interfaces/rewarder/IODefaultStakerRewardsFactory.sol";

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
