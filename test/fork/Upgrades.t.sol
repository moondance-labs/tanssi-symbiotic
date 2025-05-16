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

import {Test, console2} from "forge-std/Test.sol";

import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";

import {IODefaultOperatorRewardsOld} from "../mocks/previousVersions/IODefaultOperatorRewardsOld.sol";

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
        rewardsToken = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".rewardsToken")), (address));
        gateway = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".gateway")), (address));
        currentAdmin = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".admin")), (address));

        middleware = Middleware(middlewareAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
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
        vm.skip(true); // TODO: Remove skip once migrated, currently it expected to fail due to change in storage. Next test checks upgrade with migration
        address networkMiddlewareService = operatorRewards.i_networkMiddlewareService();
        uint48 operatorShare = operatorRewards.operatorShare();

        deployRewards.setIsTest(false);
        deployRewards.upgradeOperatorRewards(address(operatorRewards), tanssi, networkMiddlewareService);

        assertEq(operatorRewards.operatorShare(), operatorShare);
        assertEq(operatorRewards.i_networkMiddlewareService(), networkMiddlewareService);
    }

    function testUpgradeAndMigrateOperatorRewardsWithBroadcast() public {
        address networkMiddlewareService = operatorRewards.i_networkMiddlewareService();
        uint48 operatorShare = operatorRewards.operatorShare();
        IODefaultOperatorRewardsOld oldOperatorRewards = IODefaultOperatorRewardsOld(address(operatorRewards));

        uint48 testEpoch = 30; // We know this epoch has 4 eras and claimed data

        // Eras per epoch
        uint48[] memory eraIndexesPerEpoch = new uint48[](4);
        IODefaultOperatorRewardsOld.EraRoot[] memory eraRoots = new IODefaultOperatorRewardsOld.EraRoot[](4);

        eraIndexesPerEpoch[0] = oldOperatorRewards.eraIndexesPerEpoch(testEpoch, 0);
        eraIndexesPerEpoch[1] = oldOperatorRewards.eraIndexesPerEpoch(testEpoch, 1);
        eraIndexesPerEpoch[2] = oldOperatorRewards.eraIndexesPerEpoch(testEpoch, 2);
        eraIndexesPerEpoch[3] = oldOperatorRewards.eraIndexesPerEpoch(testEpoch, 3);

        // Double checking this is the forked data we want
        assertEq(eraIndexesPerEpoch[0], 576);
        assertEq(eraIndexesPerEpoch[1], 577);
        assertEq(eraIndexesPerEpoch[2], 578);
        assertEq(eraIndexesPerEpoch[3], 579); // This one, has claimed data

        eraRoots[0] = oldOperatorRewards.eraRoot(eraIndexesPerEpoch[0]);
        eraRoots[1] = oldOperatorRewards.eraRoot(eraIndexesPerEpoch[1]);
        eraRoots[2] = oldOperatorRewards.eraRoot(eraIndexesPerEpoch[2]);
        eraRoots[3] = oldOperatorRewards.eraRoot(eraIndexesPerEpoch[3]);

        address testOperator = 0x72158193a23E35817e86076246c4A3d68f8F4749;

        uint256 claimed1 = oldOperatorRewards.claimed(eraIndexesPerEpoch[3], testOperator);
        assertEq(claimed1, 10_483_452_703_380_352_520);

        address testVault = 0x94bA7BB350D8D15720C70Ba9216985AA3165B67E;
        address stakerRewardsContract = oldOperatorRewards.vaultToStakerRewardsContract(testVault);

        deployRewards.setIsTest(false);
        deployRewards.upgradeAndMigrateOperatorRewards(
            address(operatorRewards), tanssi, networkMiddlewareService, address(middleware), admin, 30
        );

        assertEq(operatorRewards.operatorShare(), operatorShare);
        assertEq(operatorRewards.i_networkMiddlewareService(), networkMiddlewareService);

        // Check eras per epoch
        assertEq(operatorRewards.eraIndexesPerEpoch(testEpoch, 0), eraIndexesPerEpoch[0]);
        assertEq(operatorRewards.eraIndexesPerEpoch(testEpoch, 1), eraIndexesPerEpoch[1]);
        assertEq(operatorRewards.eraIndexesPerEpoch(testEpoch, 2), eraIndexesPerEpoch[2]);
        assertEq(operatorRewards.eraIndexesPerEpoch(testEpoch, 3), eraIndexesPerEpoch[3]);

        // Check era root
        _compareOldAndNewEraRoots(eraRoots[0], operatorRewards.eraRoot(576));
        _compareOldAndNewEraRoots(eraRoots[1], operatorRewards.eraRoot(577));
        _compareOldAndNewEraRoots(eraRoots[2], operatorRewards.eraRoot(578));
        _compareOldAndNewEraRoots(eraRoots[3], operatorRewards.eraRoot(579));

        // Check claimed
        bytes32 testOperatorKey = 0xe86f7e1076c1cbcf4fbbb79d9aeafaa3b8450ab3a12bfa4b1ae52841ab396c10;
        assertEq(operatorRewards.claimed(eraIndexesPerEpoch[3], testOperatorKey), claimed1);

        // Check vault to staker rewards contract
        assertEq(operatorRewards.vaultToStakerRewardsContract(testVault), stakerRewardsContract);

        // Check regular operation after upgrade
        {
            // Distribute new rewards
            uint48 currentEpoch = middleware.getCurrentEpoch();
            uint48 lastEraIndex = operatorRewards.eraIndexesPerEpoch(currentEpoch - 1, 3);
            uint256 totalPoints = 1000;

            // This root + proof was generated for a single operator. Since it's a leafless merkle tree, the proof empty
            bytes32 rewardsRoot = 0x774abe8388b8b4aa79a6345dca92a0c066e54243f86c0a2b14db204dc8791474;
            bytes32[] memory proof = new bytes32[](0);

            uint256 amountToDistribute = 100 ether;
            deal(rewardsToken, address(middleware), amountToDistribute);

            vm.startPrank(gateway);
            middleware.distributeRewards(
                currentEpoch, lastEraIndex + 1, totalPoints, amountToDistribute, rewardsRoot, rewardsToken
            );
            vm.stopPrank();

            // Claim rewards
            bytes memory additionalData = abi.encode(100, new bytes(0), new bytes(0));

            IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards
                .ClaimRewardsInput({
                operatorKey: 0xe86f7e1076c1cbcf4fbbb79d9aeafaa3b8450ab3a12bfa4b1ae52841ab396c10,
                eraIndex: lastEraIndex + 1,
                totalPointsClaimable: 100,
                proof: proof,
                data: additionalData
            });

            operatorRewards.claimRewards(claimRewardsData);
        }
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

    function _compareOldAndNewEraRoots(
        IODefaultOperatorRewardsOld.EraRoot memory oldEraRoot,
        IODefaultOperatorRewards.EraRoot memory newEraRoot
    ) private pure {
        assertEq(newEraRoot.epoch, oldEraRoot.epoch);
        assertEq(newEraRoot.amount, oldEraRoot.amount);
        assertEq(newEraRoot.totalPoints, oldEraRoot.amount * oldEraRoot.tokensPerPoint);
        assertEq(newEraRoot.root, oldEraRoot.root);
        assertEq(newEraRoot.tokenAddress, oldEraRoot.tokenAddress);
    }
}
