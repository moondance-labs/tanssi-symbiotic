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
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************

import {SimpleKeyRegistry32} from "src/contracts/libraries/SimpleKeyRegistry32.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";

import {DelegatorMock} from "../mocks/symbiotic/DelegatorMock.sol";
import {OptInServiceMock} from "../mocks/symbiotic/OptInServiceMock.sol";
import {RegistryMock} from "../mocks/symbiotic/RegistryMock.sol";
import {VaultMock} from "../mocks/symbiotic/VaultMock.sol";
import {Token} from "../mocks/Token.sol";
import {MockFeeToken} from "../mocks/FeeToken.sol";

contract RewardsTest is Test {
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant AMOUNT_TO_DISTRIBUTE = 100 ether;
    uint32 public constant AMOUNT_TO_CLAIM = 20;
    uint256 public constant TOKENS_PER_POINT = 1;
    uint256 public constant EXPECTED_CLAIMABLE = uint256(AMOUNT_TO_CLAIM) * TOKENS_PER_POINT;
    uint256 public constant ADMIN_FEE = 800; // 8%
    uint48 public constant OPERATOR_SHARE = 20;
    uint48 public constant ONE_DAY = 1 days;

    // Root hash of the rewards merkle tree. It represents the rewards for the timestamp 0 for alice and bob with 20 points each
    bytes32 public constant REWARDS_ROOT = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;

    // Operator keys with which the operator is registered
    bytes32 public ALICE_KEY;
    bytes32 public BOB_KEY;
    bytes32 public ALICE_REWARDS_PROOF;
    bytes public REWARDS_ADDITIONAL_DATA;
    bytes public CLAIM_REWARDS_ADDITIONAL_DATA;

    address tanssi = makeAddr("tanssi");
    address delegatorFactory = makeAddr("delegatorFactory");
    address slasherFactory = makeAddr("slasherFactory");
    address vaultFactory = makeAddr("vaultFactory");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    NetworkMiddlewareService networkMiddlewareService;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewards stakerRewards;
    ODefaultStakerRewardsFactory stakerRewardsFactory;
    DelegatorMock delegator;
    Slasher slasher;
    VaultMock vault;
    Middleware middleware;
    Token token;
    MockFeeToken feeToken;

    function setUp() public {
        //Extract rewards data from json
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/test/unit/rewards_data.json");
        string memory json = vm.readFile(path);

        // Get payload
        ALICE_KEY = vm.parseJsonBytes32(json, "$.alice_key");
        BOB_KEY = vm.parseJsonBytes32(json, "$.bob_key");
        ALICE_REWARDS_PROOF = vm.parseJsonBytes32(json, "$.alice_rewards_proof");
        REWARDS_ADDITIONAL_DATA = vm.parseJsonBytes(json, "$.rewards_additional_data");
        CLAIM_REWARDS_ADDITIONAL_DATA = vm.parseJsonBytes(json, "$.claim_rewards_additional_data");

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
        feeToken = new MockFeeToken("Test", 100); //Extreme but it's to test when amount is 0 after a safeTransfer
        feeToken.mint(address(middleware), 1 ether);
        vm.stopPrank();

        operatorRewards = new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), OPERATOR_SHARE);

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.mockCall(
            address(vaultFactory), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );

        ODefaultStakerRewards stakerRewardsImpl = new ODefaultStakerRewards(
            address(vaultFactory), address(networkMiddlewareService), epochStartTs, NETWORK_EPOCH_DURATION
        );

        stakerRewardsFactory = new ODefaultStakerRewardsFactory(address(stakerRewardsImpl));

        stakerRewards = ODefaultStakerRewards(stakerRewardsFactory.create(params));

        vm.startPrank(address(middleware));
        operatorRewards.setStakerRewardContract(address(stakerRewards), address(vault));
        token.approve(address(operatorRewards), type(uint256).max);
        token.approve(address(stakerRewards), type(uint256).max);

        vm.startPrank(address(operatorRewards));
        token.approve(address(stakerRewards), type(uint256).max);
        vm.stopPrank();
    }

    function testConstructors() public view {
        assertEq(operatorRewards.i_network(), tanssi);
        assertEq(operatorRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(operatorRewards.s_vaultToStakerRewardsContract(address(vault)), address(stakerRewards));
        assertEq(operatorRewards.s_operatorShare(), OPERATOR_SHARE);

        assertEq(stakerRewards.NETWORK(), tanssi);
        assertEq(stakerRewards.VAULT(), address(vault));
        assertEq(stakerRewards.i_vaultFactory(), address(vaultFactory));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(stakerRewards.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(stakerRewards.i_startTime(), middleware.getEpochStartTs(0));
        assertEq(stakerRewards.s_adminFee(), ADMIN_FEE);
    }

    function _distributeRewards(
        uint48 epoch,
        uint48 timestamp,
        uint48 eraIndex,
        uint256 amount,
        address _token
    ) public {
        vm.startPrank(address(middleware));
        operatorRewards.distributeRewards(epoch, timestamp, eraIndex, amount, amount, REWARDS_ROOT, address(_token));
        vm.stopPrank();
    }

    function _generateValidProof() internal pure returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        proof[0] = 0x27e610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        return proof;
    }

    function _mockVaultActiveSharesStakeAt(bool mockShares, bool mockStake) private {
        (, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(REWARDS_ADDITIONAL_DATA, (uint256, bytes, bytes));

        if (mockShares) {
            vm.mockCall(
                address(vault),
                abi.encodeWithSelector(IVaultStorage.activeSharesAt.selector, ONE_DAY, activeSharesHint),
                abi.encode(AMOUNT_TO_DISTRIBUTE)
            );
        }
        if (mockStake) {
            vm.mockCall(
                address(vault),
                abi.encodeWithSelector(IVaultStorage.activeStakeAt.selector, ONE_DAY, activeStakeHint),
                abi.encode(AMOUNT_TO_DISTRIBUTE)
            );
        }
    }

    function _mockGetOperatorVaults() private {
        address[] memory vaults = new address[](1);
        vaults[0] = address(vault);
        vm.mockCall(
            address(middleware),
            abi.encodeWithSelector(IMiddleware.getOperatorVaults.selector, alice, ONE_DAY),
            abi.encode(1, vaults)
        );
    }

    //**************************************************************************************************
    //                                      ODefaultOperatorRewards
    //**************************************************************************************************

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************
    function testDistributeRewards() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(tanssi);
        token.transfer(address(middleware), token.balanceOf(tanssi));

        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.DistributeRewards(
            epoch, eraIndex, address(token), TOKENS_PER_POINT, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT
        );
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
    }

    function testDistributeRewardsFailsWhenMiddlewareInsufficientBalance() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(address(middleware));
        token.transfer(address(1), token.balanceOf(address(middleware)));
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, address(middleware), epoch, AMOUNT_TO_DISTRIBUTE
            )
        );
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
    }

    function testDistributeRewardsFailsWhenIsNotMiddleware() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.distributeRewards(
            epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT, address(token)
        );
    }

    function testDistributeRewardsFailsWhenTokenFeeAmountResultInZeroAmount() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        operatorRewards = new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), OPERATOR_SHARE);
        vm.startPrank(address(middleware));
        feeToken.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTransfer.selector);
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(feeToken));
    }

    function testDistributeRewardsFailsWithInvalidTotalPoints() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(tanssi);
        token.transfer(address(middleware), token.balanceOf(tanssi));

        vm.startPrank(address(middleware));
        token.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidTotalPoints.selector);
        operatorRewards.distributeRewards(
            epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, 0, REWARDS_ROOT, address(token)
        );
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimRewards() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(true, true);
        _mockGetOperatorVaults();
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        address recipient = SimpleKeyRegistry32(middleware).getOperatorByKey(ALICE_KEY);
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        vm.expectEmit(true, true, false, true);

        emit IODefaultStakerRewards.DistributeRewards(
            address(token), eraIndex, ONE_DAY, tanssi, EXPECTED_CLAIMABLE * 80 / 100, REWARDS_ADDITIONAL_DATA
        );
        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.ClaimRewards(
            recipient, address(token), eraIndex, epoch, address(this), EXPECTED_CLAIMABLE
        );
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsRootNotSet() public {
        uint48 eraIndex = 0;
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__RootNotSet.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsInvalidProof() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
        bytes32[] memory proof = new bytes32[](1);
        // Invalid proof
        proof[0] = 0xffe610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidProof.selector);
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWhenInsufficientTotalClaimable() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(true, true);
        _mockGetOperatorVaults();
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });
        operatorRewards.claimRewards(claimRewardsData);

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTotalClaimable.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWithInvalidTimestamp() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        _mockVaultActiveSharesStakeAt(true, true);
        _mockGetOperatorVaults();
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWithTooHighAdminFee() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(true, true);
        _mockGetOperatorVaults();
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
        bytes memory rewardsDataWithHighAdminFee =
            hex"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: rewardsDataWithHighAdminFee
        });
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__HighAdminFee.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWithWrongActiveShares() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockGetOperatorVaults();
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWithWrongActiveStake() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        _distributeRewards(epoch, ONE_DAY, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
        _mockGetOperatorVaults();
        _mockVaultActiveSharesStakeAt(true, false);

        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: AMOUNT_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRewardTimestamp.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    //**************************************************************************************************
    //                                          setOperatorShare
    //**************************************************************************************************

    function testSetOperatorShare() public {
        uint48 newOperatorShare = 30;
        vm.startPrank(address(middleware));
        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.SetOperatorShare(newOperatorShare);
        operatorRewards.setOperatorShare(newOperatorShare);
        assertEq(operatorRewards.s_operatorShare(), newOperatorShare);
    }

    function testSetOperatorShareNotNetworkMiddleware() public {
        uint48 newOperatorShare = 30;
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.setOperatorShare(newOperatorShare);
    }

    function testSetOperatorShareInvalidOperatorShare() public {
        uint48 newOperatorShare = 100;
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidOperatorShare.selector);
        operatorRewards.setOperatorShare(newOperatorShare);
    }

    function testSetOperatorShareAlreadySet() public {
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__AlreadySet.selector);
        operatorRewards.setOperatorShare(OPERATOR_SHARE);
    }

    //**************************************************************************************************
    //                                      setStakerRewardContract
    //**************************************************************************************************

    function testSetStakerRewardContract() public {
        address newStakerRewards = makeAddr("newStakerRewards");
        address newVault = makeAddr("newVault");
        vm.startPrank(address(middleware));
        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.SetStakerRewardContract(newStakerRewards, newVault);
        operatorRewards.setStakerRewardContract(newStakerRewards, newVault);
        assertEq(operatorRewards.s_vaultToStakerRewardsContract(newVault), newStakerRewards);
    }

    function testSetStakerRewardContractNotNetworkMiddleware() public {
        address newStakerRewards = makeAddr("newStakerRewards");
        address newVault = makeAddr("newVault");
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.setStakerRewardContract(newStakerRewards, newVault);
    }

    function testSetStakerRewardContractAlreadySet() public {
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__AlreadySet.selector);
        operatorRewards.setStakerRewardContract(address(stakerRewards), address(vault));
    }

    function testSetStakerRewardContractInvalidStakerAddress() public {
        address newStakerRewards = address(0);
        address newVault = makeAddr("newVault");
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        operatorRewards.setStakerRewardContract(newStakerRewards, newVault);
    }

    function testSetStakerRewardContractInvalidVaultAddress() public {
        address newStakerRewards = makeAddr("newStakerRewards");
        address newVault = address(0);
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        operatorRewards.setStakerRewardContract(newStakerRewards, newVault);
    }

    //**************************************************************************************************
    //                                      ODefaultStakerRewards
    //**************************************************************************************************

    //**************************************************************************************************
    //                                          constructor
    //**************************************************************************************************

    function testStakerRewardsConstructorNotVault() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.mockCall(
            address(vaultFactory),
            abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)),
            abi.encode(false)
        );

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NotVault.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndNoAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndBothAdminRole() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        IODefaultStakerRewards newStakerRewards = IODefaultStakerRewards(stakerRewardsFactory.create(params));

        assertEq(newStakerRewards.s_adminFee(), 0);
    }

    function testStakerRewardsConstructorWithInvalidAdminFee() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: stakerRewards.ADMIN_FEE_BASE() + 1,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAdminFee.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeSetRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(0),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithNoOperatorRewardsRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(0),
            network: tanssi
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(params);
    }

    function testStakerRewardsConstructorWithAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        IODefaultStakerRewards newStakerRewards = IODefaultStakerRewards(stakerRewardsFactory.create(params));

        assertEq(newStakerRewards.s_adminFee(), ADMIN_FEE);
    }

    //**************************************************************************************************
    //                                          rewardsLength
    //**************************************************************************************************

    function testRewardsLength() public {
        _setSRewardsMapping(false, address(token));
        uint256 rewardsLength = stakerRewards.rewardsLength(address(token));
        assertEq(rewardsLength, 1);
    }

    //**************************************************************************************************
    //                                            claimable
    //**************************************************************************************************

    function testClaimable() public {
        _setSRewardsMapping(false, address(token));
        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(address(token), alice, uint256(10));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddress() public {
        _setSRewardsMapping(false, address(token));

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(address(token), alice, uint256(10));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddressButMultipleRewards() public {
        Token newToken = new Token("NewToken");

        _setSRewardsMapping(true, address(newToken));

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(address(newToken), alice, uint256(10));
        assertEq(claimable, (AMOUNT_TO_DISTRIBUTE / 10) * 2);
    }

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************

    function testStakerDistributeRewardsInsufficientReward() public {
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });
        IODefaultStakerRewards newStakerRewards = IODefaultStakerRewards(stakerRewardsFactory.create(params));

        _setActiveSharesCache(address(newStakerRewards));

        vm.startPrank(address(operatorRewards));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientReward.selector);
        newStakerRewards.distributeRewards(
            ONE_DAY, eraIndex, AMOUNT_TO_CLAIM, address(feeToken), REWARDS_ADDITIONAL_DATA
        );
    }

    function testStakerDistributeRewardsWrongRole() public {
        uint48 eraIndex = 0;
        vm.warp(NETWORK_EPOCH_DURATION);

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });

        IODefaultStakerRewards newStakerRewards = IODefaultStakerRewards(stakerRewardsFactory.create(params));

        bytes32 operatoRewardsRoleHolder = newStakerRewards.OPERATOR_REWARDS_ROLE();

        _setActiveSharesCache(address(newStakerRewards));

        vm.startPrank(address(middleware));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(middleware), operatoRewardsRoleHolder
            )
        );
        newStakerRewards.distributeRewards(ONE_DAY, eraIndex, AMOUNT_TO_CLAIM, address(token), REWARDS_ADDITIONAL_DATA);
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function _setSRewardsMapping(bool multipleRewards, address _token) private {
        // For s_rewards[tokenAddress] = {Struct({amount:10 ether, timestamp:ONE_DAY})

        // Get base slot for first mapping
        bytes32 slot = keccak256(abi.encode(_token, uint256(3)));

        // Store array length
        vm.store(address(stakerRewards), slot, bytes32(uint256(multipleRewards ? 2 : 1)));

        // Store array value
        bytes32 arrayLoc = keccak256(abi.encode(slot));

        vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(10 ether)));
        // Store timestamp in next slot since it can't pack with uint256
        vm.store(address(stakerRewards), bytes32(uint256(arrayLoc) + 1), bytes32(uint256(ONE_DAY)));

        if (multipleRewards) {
            // Calculate offset for second element (index 1): 2 slots per element
            bytes32 arrayLoc2 = bytes32(uint256(arrayLoc) + 2 * 1);

            // Store second element
            vm.store(address(stakerRewards), arrayLoc2, bytes32(uint256(10 ether)));
            vm.store(address(stakerRewards), bytes32(uint256(arrayLoc2) + 1), bytes32(uint256(ONE_DAY)));

            // Verify
            (uint256 _amount, uint48 _timestamp) = stakerRewards.s_rewards(_token, 1);
            console2.log("amount, timestamp:", _amount, _timestamp);
        }
    }

    function _setActiveSharesCache(
        address _stakerRewards
    ) private {
        bytes32 slot = keccak256(abi.encode(ONE_DAY, uint256(6))); // 6 is mapping slot number for the variable _s_activeSharesCache
        vm.store(address(_stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));
    }

    function testClaimStakerRewards() public {
        _setSRewardsMapping(false, address(token));

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(address(token), alice, tanssi, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroHints() public {
        _setSRewardsMapping(false, address(token));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(address(token), alice, tanssi, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroAmount() public {
        _setSRewardsMapping(false, address(token));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(address(stakerRewards));

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);

        emit IODefaultStakerRewards.ClaimRewards(address(token), alice, tanssi, alice, 0, 1, 0);
        stakerRewards.claimRewards(alice, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidRecipient() public {
        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRecipient.selector);
        stakerRewards.claimRewards(address(0), address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsNoRewardsToClaim() public {
        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidHintsLength() public {
        _setSRewardsMapping(false, address(token));

        // 2 (fake) hints, but the reward set is only 1
        bytes memory claimRewardsWithMismatchingHintsLength =
            hex"0000000000000000000000000000000000000000000000056bc75e2d6310000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf60000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";
        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidHintsLength.selector);
        stakerRewards.claimRewards(alice, address(token), claimRewardsWithMismatchingHintsLength);
    }

    function testClaimStakerRewardsWithFakeHints() public {
        _setSRewardsMapping(false, address(token));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(
                IVaultStorage.activeSharesOfAt.selector,
                alice,
                ONE_DAY,
                hex"b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
            ),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );
        bytes memory claimRewardsWithFakeHints =
            hex"0000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(address(token), alice, tanssi, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, address(token), claimRewardsWithFakeHints);
    }

    function testClaimStakerRewardsButWithFakeTokenAddressNoRewardsToClaim() public {
        _setSRewardsMapping(false, address(token));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, address(1), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsButMultipleRewards() public {
        _setSRewardsMapping(true, address(token));
        _setActiveSharesCache(address(stakerRewards));

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), (AMOUNT_TO_DISTRIBUTE / 10) * 2);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, ONE_DAY, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(
            address(token), alice, tanssi, alice, 0, 2, (AMOUNT_TO_DISTRIBUTE / 10) * 2
        );

        stakerRewards.claimRewards(alice, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
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

    function _setClaimableAdminFee(
        address _token
    ) private {
        // TODO
        // For s_claimableAdminFee[epoch][tokenAddress]

        // Get base slot for first mapping
        bytes32 slot = keccak256(abi.encode(_token, uint256(5))); // For s_claimableAdminFee mapping at slot 4

        // Store value
        vm.store(address(stakerRewards), slot, bytes32(uint256(10 ether)));
    }

    function testClaimAdminFee() public {
        _setClaimableAdminFee(address(token));

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), 10 ether);

        vm.startPrank(address(middleware));
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.ClaimAdminFee(tanssi, address(token), 10 ether);
        stakerRewards.claimAdminFee(tanssi, address(token));
    }

    function testClaimAdminFeeInsufficientAdminFee() public {
        vm.startPrank(address(middleware));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientAdminFee.selector);
        stakerRewards.claimAdminFee(tanssi, address(token));
    }

    function testClaimAdminFeeWithInvalidRole() public {
        address randomUser = makeAddr("randomUser");

        bytes32 adminFeeClaimRole = stakerRewards.ADMIN_FEE_CLAIM_ROLE();
        vm.startPrank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, adminFeeClaimRole
            )
        );
        stakerRewards.claimAdminFee(tanssi, address(token));
    }
}
