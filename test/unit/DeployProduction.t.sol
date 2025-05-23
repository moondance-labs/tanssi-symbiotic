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

import {Test, Vm} from "forge-std/Test.sol";

import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";

import {DeployProduction} from "script/DeployProduction.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract DeployProductionTest is Test {
    DeployProduction deployProduction;

    function setUp() public {
        deployProduction = new DeployProduction();
    }

    function testDeployWithBroadcast() public {
        vm.chainId(11_155_111);
        (address middlewareAddress, address operatorRewardsAddress, address stakerRewardsFactoryAddress) =
            deployProduction.deploy();

        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/chain_data.json");
        string memory json = vm.readFile(path);
        uint256 chainId = block.chainid;
        string memory jsonPath = string.concat("$.", vm.toString(chainId));
        address admin = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".admin")), (address));
        address tanssi = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".tanssi")), (address));
        address gateway = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".gateway")), (address));
        address forwarder = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".forwarder")), (address));
        DeployProduction.Entities memory entities =
            DeployProduction.Entities({admin: admin, tanssi: tanssi, gateway: gateway, forwarder: forwarder});

        uint256 adminPrivateKey =
            vm.envOr("PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
        address initialAdmin = vm.addr(adminPrivateKey);

        _checkAddressesAndRoles(
            middlewareAddress, operatorRewardsAddress, stakerRewardsFactoryAddress, entities, initialAdmin
        );
    }

    function testDeployLocal() public {
        HelperConfig helperConfig = new HelperConfig();
        address initialAdmin = makeAddr("initialAdmin");
        address admin = makeAddr("admin");
        address tanssi = makeAddr("tanssi");
        address gateway = makeAddr("gateway");
        address forwarder = makeAddr("forwarder");
        DeployProduction.Entities memory entities =
            DeployProduction.Entities({admin: admin, tanssi: tanssi, gateway: gateway, forwarder: forwarder});

        (address middlewareAddress, address operatorRewardsAddress, address stakerRewardsFactoryAddress) =
            deployProduction.localDeploy(helperConfig, entities, initialAdmin);

        _checkAddressesAndRoles(
            middlewareAddress, operatorRewardsAddress, stakerRewardsFactoryAddress, entities, initialAdmin
        );
    }

    function _checkAddressesAndRoles(
        address middlewareAddress,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress,
        DeployProduction.Entities memory entities,
        address initialAdmin
    ) internal view {
        Middleware middleware = Middleware(middlewareAddress);
        assertTrue(middleware.hasRole(keccak256("GATEWAY_ROLE"), entities.gateway));
        // assertTrue(middleware.hasRole(keccak256("FORWARDER_ROLE"), entities.forwarder)); // Not needed initially
        assertTrue(middleware.hasRole(middleware.DEFAULT_ADMIN_ROLE(), entities.admin));
        assertTrue(middleware.hasRole(middleware.DEFAULT_ADMIN_ROLE(), initialAdmin));

        ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        assertTrue(operatorRewards.hasRole(operatorRewards.MIDDLEWARE_ROLE(), middlewareAddress));
        assertTrue(operatorRewards.hasRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), middlewareAddress));
        assertTrue(operatorRewards.hasRole(operatorRewards.DEFAULT_ADMIN_ROLE(), entities.admin));
        assertTrue(operatorRewards.hasRole(operatorRewards.DEFAULT_ADMIN_ROLE(), initialAdmin));

        assertNotEq(stakerRewardsFactoryAddress, address(0));
    }
}
