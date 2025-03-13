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

import {Script, console2} from "forge-std/Script.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";

contract DeployRewards is Script {
    ODefaultStakerRewardsFactory public stakerRewardsFactory;
    ODefaultOperatorRewards public operatorRewards;
    ODefaultStakerRewards public stakerRewardsImpl;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));

    bool isTest = false;

    struct DeployParams {
        address vault;
        address vaultFactory;
        uint256 adminFee;
        address defaultAdminRole;
        address adminFeeClaimRole;
        address adminFeeSetRole;
        address network;
        address networkMiddlewareService;
        uint48 startTime;
        uint48 epochDuration;
        uint48 operatorShare;
    }

    event Done();

    constructor(
        bool _isTest
    ) {
        isTest = _isTest;
    }

    function deployOperatorRewardsContract(
        address network,
        address networkMiddlewareService,
        uint48 operatorShare,
        address owner
    ) public returns (address) {
        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }
        ODefaultOperatorRewards operatorRewardsImpl = new ODefaultOperatorRewards(network, networkMiddlewareService);
        operatorRewards = ODefaultOperatorRewards(address(new ERC1967Proxy(address(operatorRewardsImpl), "")));
        operatorRewards.initialize(operatorShare, owner);
        console2.log("Operator rewards contract deployed at address: ", address(operatorRewards));
        if (!isTest) {
            vm.stopBroadcast();
        }
        return address(operatorRewards);
    }

    function deployStakerRewardsFactoryContract(
        address vaultFactory,
        address networkMiddlewareService,
        uint48 startTime,
        uint48 epochDuration
    ) public returns (address) {
        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }
        stakerRewardsFactory =
            new ODefaultStakerRewardsFactory(vaultFactory, networkMiddlewareService, startTime, epochDuration);
        console2.log("Staker rewards factory deployed at address: ", address(stakerRewardsFactory));

        if (!isTest) {
            vm.stopBroadcast();
        }

        return address(stakerRewardsFactory);
    }

    function run(
        DeployParams calldata params
    ) external {
        deployOperatorRewardsContract(
            params.network, params.networkMiddlewareService, params.operatorShare, params.defaultAdminRole
        );
        deployStakerRewardsFactoryContract(params.vaultFactory, params.network, params.startTime, params.epochDuration);
        emit Done();
    }
}
