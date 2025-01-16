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
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {ScaleCodec} from "@snowbridge/src/utils/ScaleCodec.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************

import {SimpleKeyRegistry32} from "src/contracts/libraries/SimpleKeyRegistry32.sol";
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
    uint32 public constant TOKEN_PER_POINT = 1;
    uint256 public constant EXPECTED_CLAIMABLE = uint256(AMOUNT_TO_CLAIM) * uint256(TOKEN_PER_POINT) * 10 ** 18;
    uint256 public constant ADMIN_FEE = 800; // 8%
    bytes32 public constant REWARDS_ROOT = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;
    bytes32 public constant ALICE_KEY = 0x0404040404040404040404040404040404040404040404040404040404040404;
    bytes32 public constant BOB_KEY = 0x0505050505050505050505050505050505050505050505050505050505050505;

    bytes public constant REWARDS_ADDITIONAL_DATA =
        hex"00000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes public constant CLAIM_REWARDS_ADDITIONAL_DATA =
        hex"0000000000000000000000000000000000000000000000056bc75e2d6310000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000";

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

    function testConstructors() public view {
        assertEq(operatorRewards.i_network(), tanssi);
        assertEq(operatorRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(operatorRewards.i_token(), address(token));

        assertEq(stakerRewards.i_network(), tanssi);
        assertEq(stakerRewards.i_vaultFactory(), address(vaultFactory));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(stakerRewards.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(stakerRewards.i_token(), address(token));
        assertEq(stakerRewards.s_vault(), address(vault));
        assertEq(stakerRewards.s_adminFee(), ADMIN_FEE);
    }

    function _distributeRewards(uint48 epoch, uint256 amount) public {
        vm.startPrank(address(middleware));
        operatorRewards.distributeRewards(epoch, amount, amount, REWARDS_ROOT);
        vm.stopPrank();
    }

    function _generateValidProof() internal pure returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        proof[0] = 0x27e610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        return proof;
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

    //**************************************************************************************************
    //                                      ODefaultOperatorRewards
    //**************************************************************************************************

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************
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

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimRewards() public {
        uint48 epoch = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _distributeRewards(epoch, AMOUNT_TO_DISTRIBUTE);

        address recipient = SimpleKeyRegistry32(NetworkMiddlewareService(networkMiddlewareService).middleware(tanssi))
            .getOperatorByKey(ALICE_KEY);
        bytes32[] memory proof = _generateValidProof();

        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.DistributeRewards(tanssi, EXPECTED_CLAIMABLE * 80 / 100, REWARDS_ADDITIONAL_DATA);
        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.ClaimRewards(recipient, epoch, msg.sender, EXPECTED_CLAIMABLE);
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

    //**************************************************************************************************
    //                                      ODefaultStakerRewards
    //**************************************************************************************************

    //**************************************************************************************************
    //                                          constructor
    //**************************************************************************************************

    function testStakerRewardsConstructorNotVault() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.mockCall(
            address(vaultFactory),
            abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)),
            abi.encode(false)
        );

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NotVault.selector);
        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndNoAdminFeeClaimRoleHolder() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndBothAdminRole() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        ODefaultStakerRewards sr = new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );

        assertEq(sr.s_adminFee(), 0);
    }

    function testStakerRewardsConstructorWithInvalidAdminFee() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: stakerRewards.ADMIN_FEE_BASE() + 1,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAdminFee.selector);
        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );
    }

    function testStakerRewardsConstructorWithNoAdminFeeSetRoleHolder() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(0)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );
    }

    function testStakerRewardsConstructorWithNoAdminFeeClaimRoleHolder() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );
    }

    function testStakerRewardsConstructorWithAdminFeeClaimRoleHolder() public {
        uint48 epochStartTs = middleware.getEpochStartTs(0);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(token),
            params
        );

        assertEq(stakerRewards.s_adminFee(), ADMIN_FEE);
    }

    //**************************************************************************************************
    //                                          getEpochStartTs
    //**************************************************************************************************

    function testGetEpochStartTs() public view {
        uint48 epoch = 0;
        uint48 epochStartTs = middleware.getEpochStartTs(epoch);
        assertEq(stakerRewards.getEpochStartTs(epoch), epochStartTs);
    }

    //**************************************************************************************************
    //                                          rewardsLength
    //**************************************************************************************************

    function testRewardsLength() public {
        uint48 epoch = 0;
        _setSRewardsMapping();
        uint256 rewardsLength = stakerRewards.rewardsLength(epoch);
        assertEq(rewardsLength, 1);
    }

    //**************************************************************************************************
    //                                          setVault
    //**************************************************************************************************

    function testSetVault() public {
        address newVault = makeAddr("newVault");
        vm.mockCall(
            address(vaultFactory),
            abi.encodeWithSelector(IRegistry.isEntity.selector, address(newVault)),
            abi.encode(true)
        );
        vm.prank(address(middleware));
        stakerRewards.setVault(newVault);
        assertEq(stakerRewards.s_vault(), newVault);
    }

    function testSetVaultAlreadySet() public {
        vm.prank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__AlreadySet.selector);
        stakerRewards.setVault(address(vault));
    }

    function testSetVaultNotVault() public {
        address notVault = makeAddr("notVault");
        vm.mockCall(
            address(vaultFactory),
            abi.encodeWithSelector(IRegistry.isEntity.selector, address(notVault)),
            abi.encode(false)
        );
        vm.prank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NotVault.selector);
        stakerRewards.setVault(notVault);
    }

    function testSetVaultNotAuthorized() public {
        address randomUser = makeAddr("randomUser");
        bytes32 defaultAdminRole = stakerRewards.DEFAULT_ADMIN_ROLE();
        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, defaultAdminRole
            )
        );
        stakerRewards.setVault(address(vault));
    }
    //**************************************************************************************************
    //                                            claimable
    //**************************************************************************************************

    function testClaimable() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStartTs(epoch);
        _setSRewardsMapping();

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, uint256(10));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************

    function testStakerDistributeRewardsInsufficientReward() public {
        uint48 epoch = 0;
        uint48 epochStartTs = middleware.getEpochStartTs(epoch);
        vm.warp(NETWORK_EPOCH_DURATION);

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });
        stakerRewards = new ODefaultStakerRewards(
            tanssi,
            address(vaultFactory),
            address(networkMiddlewareService),
            epochStartTs,
            NETWORK_EPOCH_DURATION,
            address(feeToken),
            params
        );

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 5 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.startPrank(address(middleware));
        feeToken.approve(address(stakerRewards), type(uint256).max);

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientReward.selector);
        stakerRewards.distributeRewards(epoch, AMOUNT_TO_CLAIM, REWARDS_ADDITIONAL_DATA);
    }
    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function _setSRewardsMapping() private {
        // For s_rewards[0] = [10 ether]
        bytes32 slot = keccak256(abi.encode(uint48(0), uint256(2))); // 1 is mapping slot

        // Get array storage location
        bytes32 arrayLoc = keccak256(abi.encode(slot));

        // Store array length (1)
        vm.store(address(stakerRewards), slot, bytes32(uint256(1)));

        // Store array value
        vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(10 ether)));
    }

    function testClaimStakerRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStartTs(epoch);

        _setSRewardsMapping();
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStartTs(epoch);

        _setSRewardsMapping();
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroAmount() public {
        uint48 epoch = 0;

        _setSRewardsMapping();
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, alice, epoch, alice, 0, 1, 0);
        stakerRewards.claimRewards(alice, epoch, CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidRecipient() public {
        uint48 epoch = 0;

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRecipient.selector);
        stakerRewards.claimRewards(address(0), epoch, CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsNoRewardsToClaim() public {
        uint48 epoch = 0;

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, epoch, CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidHintsLength() public {
        uint48 epoch = 0;

        _setSRewardsMapping();

        bytes memory claimRewardsAdditionalDataWrong =
            hex"0000000000000000000000000000000000000000000000056bc75e2d6310000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf60000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";
        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidHintsLength.selector);
        stakerRewards.claimRewards(alice, epoch, claimRewardsAdditionalDataWrong);
    }

    function testClaimStakerRewardsWithFakeHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStartTs(epoch);

        _setSRewardsMapping();
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(
                IVaultStorage.activeSharesOfAt.selector,
                alice,
                epochTs,
                hex"b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
            ),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );
        bytes memory claimRewardsAdditionalDataFake =
            hex"0000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, claimRewardsAdditionalDataFake);
    }

    //**************************************************************************************************
    //                                      setAdminFee
    //**************************************************************************************************

    function testSetAdminFee() public {
        uint256 newFee = ADMIN_FEE + 100;
        vm.startPrank(address(middleware));
        vm.expectEmit(true, false, false, true);
        emit IODefaultStakerRewards.SetAdminFee(newFee);
        stakerRewards.setAdminFee(newFee);
        assertEq(stakerRewards.s_adminFee(), newFee);
    }

    function testSetAdminFeeAlreadySet() public {
        uint256 newFee = ADMIN_FEE;
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__AlreadySet.selector);
        stakerRewards.setAdminFee(newFee);
    }

    function testSetAdminFeeInvalidAdminFee() public {
        uint256 newFee = stakerRewards.ADMIN_FEE_BASE() + 1;
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAdminFee.selector);
        stakerRewards.setAdminFee(newFee);
    }

    function testSetAdminFeeWithInvalidRole() public {
        uint256 newFee = 700;
        bytes32 adminFeeSetRole = stakerRewards.ADMIN_FEE_SET_ROLE();
        address randomUser = makeAddr("randomUser");
        vm.startPrank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, adminFeeSetRole
            )
        );
        stakerRewards.setAdminFee(newFee);
    }

    //**************************************************************************************************
    //                                      claimAdminFee
    //**************************************************************************************************

    function testClaimAdminFee() public {
        uint48 epoch = 0;

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), 10 ether);

        bytes32 slot = keccak256(abi.encode(epoch, uint256(4))); // 4 is mapping slot number
        vm.store(address(stakerRewards), slot, bytes32(uint256(10 ether)));

        vm.startPrank(address(middleware));
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.ClaimAdminFee(tanssi, 10 ether);
        stakerRewards.claimAdminFee(tanssi, epoch);
    }

    function testClaimAdminFeeInsufficientAdminFee() public {
        uint48 epoch = 0;

        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientAdminFee.selector);
        stakerRewards.claimAdminFee(tanssi, epoch);
    }

    function testClaimAdminFeeWithInvalidRole() public {
        uint48 epoch = 0;
        address randomUser = makeAddr("randomUser");

        bytes32 adminFeeClaimRole = stakerRewards.ADMIN_FEE_CLAIM_ROLE();
        vm.startPrank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, adminFeeClaimRole
            )
        );
        stakerRewards.claimAdminFee(tanssi, epoch);
    }
}
