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

import {Test} from "forge-std/Test.sol";

import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";

contract MiddlewareTest is Test {
    Middleware middleware;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewards stakerRewards;
    DeployTanssiEcosystem deployTanssiEcosystem;
    DeployRewards deployRewards;
    address tanssi;
    address admin;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/chain_data.json");
        string memory json = vm.readFile(path);

        uint256 chainId = block.chainid;
        string memory jsonPath = string.concat("$.", vm.toString(chainId));

        address middlewareAddress = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".middleware")), (address));
        address operatorRewardsAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorRewards")), (address));
        address stakerRewardsAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".stakerRewards")), (address));

        middleware = Middleware(middlewareAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        stakerRewards = ODefaultStakerRewards(stakerRewardsAddress);

        deployRewards = new DeployRewards();
        deployRewards.setIsTest(false);
        deployTanssiEcosystem = new DeployTanssiEcosystem();
        tanssi = IOBaseMiddlewareReader(address(middleware)).NETWORK();
        admin = deployTanssiEcosystem.tanssi(); // Loaded from the env OWNER_PRIVATE_KEY

        // Actual admin in the 3 contracts, we use its account to set the admin role to our admin which will run using broadcast
        vm.startPrank(0x8f7b28C2A36E805F4024c1AE1e96a4B75E50A512);
        operatorRewards.grantRole(operatorRewards.DEFAULT_ADMIN_ROLE(), admin);
        stakerRewards.grantRole(stakerRewards.DEFAULT_ADMIN_ROLE(), admin);
        middleware.grantRole(middleware.DEFAULT_ADMIN_ROLE(), admin);
        vm.stopPrank();
    }

    function testUpgradeMiddleware() public {
        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");

        IOBaseMiddlewareReader reader = IOBaseMiddlewareReader(address(middleware));

        uint48 currentEpoch = reader.getCurrentEpoch();
        address network = reader.NETWORK();
        uint256 operatorsLength = reader.operatorsLength();

        deployTanssiEcosystem.upgradeMiddlewareBroadcast(
            address(middleware), 1, newOperatorRewardsAddress, newStakerRewardsFactoryAddress
        );

        assertEq(middleware.i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(middleware.i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
        assertEq(reader.getCurrentEpoch(), currentEpoch);
        assertEq(reader.NETWORK(), network);
        assertEq(reader.operatorsLength(), operatorsLength);
    }

    function testUpgradeMiddlewareFailsIfUnexpectedVersion() public {
        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        vm.expectRevert("Middleware version is not expected, cannot upgrade");
        deployTanssiEcosystem.upgradeMiddleware(
            address(middleware), 2, newOperatorRewardsAddress, newStakerRewardsFactoryAddress, address(0)
        );
    }

    function testUpgradeRewardsOperatorWithBroadcast() public {
        address networkMiddlewareService = operatorRewards.i_networkMiddlewareService();
        uint48 operatorShare = operatorRewards.operatorShare();

        deployRewards.setIsTest(false);
        deployRewards.upgradeOperatorRewards(address(operatorRewards), tanssi, networkMiddlewareService);

        assertEq(operatorRewards.operatorShare(), operatorShare);
        assertEq(operatorRewards.i_networkMiddlewareService(), networkMiddlewareService);
    }

    function testUpgradeStakerRewardsWithBroadcast() public {
        address vault = stakerRewards.i_vault();
        address network = stakerRewards.i_network();
        address networkMiddlewareService = stakerRewards.i_networkMiddlewareService();

        deployRewards.upgradeStakerRewards(address(stakerRewards), networkMiddlewareService, vault, network);

        assertEq(stakerRewards.i_vault(), vault);
        assertEq(stakerRewards.i_network(), network);
        assertEq(stakerRewards.i_networkMiddlewareService(), networkMiddlewareService);
    }
}
