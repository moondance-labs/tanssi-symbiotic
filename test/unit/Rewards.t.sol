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

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {NetworkMiddlewareService} from "@symbioticfi/core/src/contracts/service/NetworkMiddlewareService.sol";
import {NetworkRegistry} from "@symbioticfi/core/src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "@symbioticfi/core/src/contracts/OperatorRegistry.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";

import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IVaultStorage} from "@symbiotic/interfaces/vault/IVaultStorage.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

import {ScaleCodec} from "@snowbridge/src/utils/ScaleCodec.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";

import {DelegatorMock} from "../mocks/symbiotic/DelegatorMock.sol";
import {OptInServiceMock} from "../mocks/symbiotic/OptInServiceMock.sol";
import {RegistryMock} from "../mocks/symbiotic/RegistryMock.sol";
import {VaultMock} from "../mocks/symbiotic/VaultMock.sol";
import {Token} from "../mocks/Token.sol";
import {MockFeeToken} from "../mocks/FeeToken.sol";

contract RewardsTest is Test {
    event DistributeRewards(uint48 indexed epoch, bytes32 indexed root);

    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant AMOUNT_TO_DISTRIBUTE = 100 ether;
    uint32 public constant AMOUNT_TO_CLAIM = 20;
    uint256 public constant ADMIN_FEE = 8;
    bytes32 public constant REWARDS_ROOT = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;
    bytes32 public constant ALICE_KEY = 0x0404040404040404040404040404040404040404040404040404040404040404;
    bytes32 public constant BOB_KEY = 0x0505050505050505050505050505050505050505050505050505050505050505;

    bytes public constant REWARDS_ADDITIONAL_DATA =
        hex"00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    address tanssi = makeAddr("tanssi");
    address delegatorFactory = makeAddr("delegatorFactory");
    address slasherFactory = makeAddr("slasherFactory");
    address vaultFactory = makeAddr("vaultFactory");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    NetworkMiddlewareService networkMiddlewareService;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewards stakerRewards;
    DelegatorMock delegator;
    Slasher slasher;
    VaultMock vault;
    Middleware middleware;
    Token token;
    MockFeeToken feeToken;

    function setUp() public {
        NetworkRegistry networkRegistry = new NetworkRegistry();
        OperatorRegistry operatorRegistry = new OperatorRegistry();
        OptInService operatorNetworkOptIn =
            new OptInService(address(operatorRegistry), address(networkRegistry), "OperatorNetworkOptInService");
        OptInService operatorVaultOptIn =
            new OptInService(address(operatorRegistry), address(networkRegistry), "OperatorVaultOptInService");

        networkMiddlewareService = new NetworkMiddlewareService(address(networkRegistry));
        middleware = new Middleware(
            tanssi,
            address(operatorRegistry),
            address(networkRegistry),
            address(operatorNetworkOptIn),
            tanssi,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );

        delegator = new DelegatorMock(
            address(networkRegistry),
            address(vaultFactory),
            address(operatorVaultOptIn),
            address(operatorNetworkOptIn),
            delegatorFactory,
            0
        );
        slasher = new Slasher(address(vaultFactory), address(networkMiddlewareService), slasherFactory, 0);

        vault = new VaultMock(delegatorFactory, slasherFactory, address(vaultFactory));
        vault.setDelegator(address(delegator));
        vm.store(address(delegator), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        uint48 epochStartTs = middleware.getEpochStartTs(0);

        vm.startPrank(tanssi);
        token = new Token("Test");
        token.transfer(address(middleware), token.balanceOf(tanssi));
        networkRegistry.registerNetwork();
        networkMiddlewareService.setMiddleware(address(middleware));

        vm.startPrank(alice);
        operatorRegistry.registerOperator();
        operatorNetworkOptIn.optIn(tanssi);

        vm.startPrank(bob);
        operatorRegistry.registerOperator();
        operatorNetworkOptIn.optIn(tanssi);

        vm.startPrank(tanssi);
        middleware.registerOperator(alice, ALICE_KEY);
        middleware.registerOperator(bob, BOB_KEY);

        vm.startPrank(address(middleware));
        feeToken = new MockFeeToken("Test", 100); //Extreme but to test that's a possibility
        vm.stopPrank();

        console2.log("Middleware for network: ", networkMiddlewareService.middleware(tanssi));
        operatorRewards = new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(token));

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.mockCall(
            address(vaultFactory), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );
        stakerRewards = new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );

        vm.startPrank(address(middleware));
        operatorRewards.setStakerRewardContract(address(stakerRewards));
        token.approve(address(operatorRewards), type(uint256).max);
        token.approve(address(stakerRewards), type(uint256).max);

        vm.startPrank(address(operatorRewards));
        token.approve(address(stakerRewards), type(uint256).max);
        vm.stopPrank();
    }

    function _distributeRewards(uint48 epoch, uint256 amount) public {
        vm.startPrank(address(middleware));
        operatorRewards.distributeRewards(epoch, amount, amount, REWARDS_ROOT);
        vm.stopPrank();
    }

    function testDistributeRewards() public {
        uint48 epoch = 0;

        vm.startPrank(tanssi);
        token.transfer(address(middleware), token.balanceOf(tanssi));

        vm.expectEmit(true, true, false, true);
        emit DistributeRewards(epoch, REWARDS_ROOT);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);
    }

    function testDistributeRewardsFailsWhenMiddlewareInsufficientBalance() public {
        uint48 epoch = 0;

        vm.startPrank(address(middleware));
        token.transfer(address(1), token.balanceOf(address(middleware)));
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, address(middleware), epoch, AMOUNT_TO_DISTRIBUTE
            )
        );
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);
    }

    function testDistributeRewardsFailsWhenIsNotMiddleware() public {
        uint48 epoch = 0;

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT);
    }

    function testDistributeRewardsFailsWhenTokenFeeAmountResultInZeroAmount() public {
        uint48 epoch = 0;

        operatorRewards = new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(feeToken));
        vm.startPrank(address(middleware));
        feeToken.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTransfer.selector);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);
    }

    function _mockVaultActiveSharesStakeAt(uint48 epoch, bool mockShares, bool mockStake) private {
        uint48 epochTs = middleware.getEpochStartTs(epoch);
        (, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(REWARDS_ADDITIONAL_DATA, (uint256, bytes, bytes));

        if (mockShares) {
            vm.mockCall(
                address(vault),
                abi.encodeWithSelector(IVaultStorage.activeSharesAt.selector, epochTs, activeSharesHint),
                abi.encode(AMOUNT_TO_DISTRIBUTE)
            );
        }
        if (mockStake) {
            vm.mockCall(
                address(vault),
                abi.encodeWithSelector(IVaultStorage.activeStakeAt.selector, epochTs, activeStakeHint),
                abi.encode(AMOUNT_TO_DISTRIBUTE)
            );
        }
    }

    function testClaimRewards() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        bytes32[] memory proof = _generateValidProof();
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsRootNotSet() public {
        uint48 epoch = 0;
        bytes32[] memory proof = _generateValidProof();
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__RootNotSet.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsInvalidProof() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);
        bytes32[] memory proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        proof[0] = 0xffe610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidProof.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsWhenInsufficientTotalClaimable() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);
        bytes32[] memory proof = _generateValidProof();
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTotalClaimable.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsWithInvalidTimestamp() public {
        uint48 epoch = 0;
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        bytes32[] memory proof = _generateValidProof();

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsWithTooHighAdminFee() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        bytes memory badRewardsData =
            hex"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes32[] memory proof = _generateValidProof();
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__HighAdminFee.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, badRewardsData);
    }

    function testClaimRewardsWithWrongActiveShares() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        bytes32[] memory proof = _generateValidProof();
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function testClaimRewardsWithWrongActiveStake() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        _mockVaultActiveSharesStakeAt(epoch, true, false);

        bytes32[] memory proof = _generateValidProof();
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(ALICE_KEY, epoch, AMOUNT_TO_CLAIM, proof, REWARDS_ADDITIONAL_DATA);
    }

    function _generateValidProof() internal pure returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        proof[0] = 0x27e610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        return proof;
    }
}
