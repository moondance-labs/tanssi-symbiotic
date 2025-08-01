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
import {HelperConfig} from "script/HelperConfig.s.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";

contract UpgradesTest is Test {
    Middleware middleware;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewards stakerRewards;
    DeployTanssiEcosystem deployTanssiEcosystem;
    DeployRewards deployRewards;
    address tanssi;
    address admin; // Used to run tests
    address currentAdmin; // Current admin in the 3 contracts, we use its account to set the admin role to test admin which will run using broadcast
    address rewardsToken;
    address gateway;

    function setUp() public {
        HelperConfig helperConfig = new HelperConfig();
        address middlewareAddress;
        address operatorRewardsAddress;
        (currentAdmin, tanssi, gateway,, middlewareAddress, operatorRewardsAddress, rewardsToken) =
            helperConfig.activeEntities();
        middleware = Middleware(middlewareAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        (string memory json, string memory jsonPath) = helperConfig.getJsonAndPathForChain();

        address stakerRewardsAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".vaults[0].stakerRewards")), (address));

        stakerRewards = ODefaultStakerRewards(stakerRewardsAddress);

        deployRewards = new DeployRewards();
        deployRewards.setIsTest(false);
        deployTanssiEcosystem = new DeployTanssiEcosystem();
        tanssi = IOBaseMiddlewareReader(address(middleware)).NETWORK();
        admin = deployTanssiEcosystem.tanssi(); // Loaded from the env OWNER_PRIVATE_KEY

        vm.startPrank(currentAdmin);
        operatorRewards.grantRole(operatorRewards.DEFAULT_ADMIN_ROLE(), admin);
        stakerRewards.grantRole(stakerRewards.DEFAULT_ADMIN_ROLE(), admin);
        middleware.grantRole(middleware.DEFAULT_ADMIN_ROLE(), admin);
        vm.stopPrank();
    }

    function testUpgradeMiddleware() public {
        address stakerRewardsFactory = middleware.i_stakerRewardsFactory();
        IOBaseMiddlewareReader reader = IOBaseMiddlewareReader(address(middleware));

        uint48 currentEpoch = reader.getCurrentEpoch();
        address network = reader.NETWORK();
        uint256 operatorsLength = reader.operatorsLength();

        deployTanssiEcosystem.upgradeMiddlewareBroadcast(address(middleware), 1);

        assertEq(middleware.i_operatorRewards(), address(operatorRewards));
        assertEq(middleware.i_stakerRewardsFactory(), stakerRewardsFactory);
        assertEq(reader.getCurrentEpoch(), currentEpoch);
        assertEq(reader.NETWORK(), network);
        assertEq(reader.operatorsLength(), operatorsLength);
    }

    function testUpgradeMiddlewareFailsIfUnexpectedVersion() public {
        vm.expectRevert("Middleware version is not expected, cannot upgrade");
        deployTanssiEcosystem.upgradeMiddleware(address(middleware), 2, address(0));
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
        address network = stakerRewards.i_network();
        address networkMiddlewareService = stakerRewards.i_networkMiddlewareService();

        deployRewards.upgradeStakerRewards(address(stakerRewards), networkMiddlewareService, network);

        assertEq(stakerRewards.i_network(), network);
        assertEq(stakerRewards.i_networkMiddlewareService(), networkMiddlewareService);
    }
}
