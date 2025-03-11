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
import {BaseMiddlewareReader} from "@symbiotic-middleware/middleware/BaseMiddlewareReader.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************

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

import {DeployRewards} from "script/DeployRewards.s.sol";

contract RewardsTest is Test {
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant AMOUNT_TO_DISTRIBUTE = 100 ether;
    uint32 public constant AMOUNT_TO_CLAIM = 20;
    uint256 public constant TOKENS_PER_POINT = 1;
    uint256 public constant EXPECTED_CLAIMABLE = uint256(AMOUNT_TO_CLAIM) * TOKENS_PER_POINT;
    uint256 public constant ADMIN_FEE = 800; // 8%
    uint48 public constant OPERATOR_SHARE = 2000;

    // Root hash of the rewards merkle tree. It represents the rewards for the epoch 0 for alice and bob with 20 points each
    bytes32 public constant REWARDS_ROOT = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;

    // Operator keys with which the operator is registered
    bytes32 public ALICE_KEY;
    bytes32 public BOB_KEY;
    bytes32 public ALICE_REWARDS_PROOF;
    bytes public REWARDS_ADDITIONAL_DATA;
    bytes public CLAIM_REWARDS_ADDITIONAL_DATA;

    address tanssi = makeAddr("tanssi");
    address owner = makeAddr("owner");
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
    DeployRewards deployRewards;

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
        address readHelper = address(new BaseMiddlewareReader());

        deployRewards = new DeployRewards();
        address operatorRewardsAddress = deployRewards.deployOperatorRewardsContract(
            tanssi, address(networkMiddlewareService), OPERATOR_SHARE, owner
        );
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        delegator = new DelegatorMock(
            address(networkRegistry),
            address(vaultFactory),
            address(operatorVaultOptIn),
            address(operatorNetworkOptIn),
            delegatorFactory,
            0
        );

        vault = new VaultMock(delegatorFactory, slasherFactory, address(vaultFactory));
        vault.setDelegator(address(delegator));
        vm.store(address(delegator), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        ODefaultStakerRewards stakerRewardsImpl = new ODefaultStakerRewards(
            address(vaultFactory), address(networkMiddlewareService), uint48(block.timestamp), NETWORK_EPOCH_DURATION
        );

        vm.mockCall(
            address(vaultFactory), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            vault: address(vault),
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(tanssi),
            adminFeeClaimRoleHolder: address(tanssi),
            adminFeeSetRoleHolder: address(tanssi),
            operatorRewardsRoleHolder: address(operatorRewards),
            network: tanssi
        });
        stakerRewardsFactory = new ODefaultStakerRewardsFactory(address(stakerRewardsImpl));
        stakerRewards = ODefaultStakerRewards(stakerRewardsFactory.create(stakerRewardsParams));

        Middleware _middlewareImpl = new Middleware(operatorRewardsAddress, address(stakerRewards));
        middleware = Middleware(address(new ERC1967Proxy(address(_middlewareImpl), "")));
        Middleware(address(middleware)).initialize(
            tanssi,
            address(operatorRegistry),
            address(networkRegistry),
            address(operatorNetworkOptIn),
            tanssi,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW,
            readHelper
        );
        slasher = new Slasher(address(vaultFactory), address(networkMiddlewareService), slasherFactory, 0);

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
        middleware.registerOperator(alice, abi.encode(ALICE_KEY), address(0));
        middleware.registerOperator(bob, abi.encode(BOB_KEY), address(0));

        vm.startPrank(address(middleware));
        feeToken = new MockFeeToken("Test", 100); //Extreme but it's to test when amount is 0 after a safeTransfer
        feeToken.mint(address(middleware), 1 ether);
        vm.stopPrank();

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
        assertEq(operatorRewards.vaultToStakerRewardsContract(address(vault)), address(stakerRewards));
        assertEq(operatorRewards.operatorShare(), OPERATOR_SHARE);

        assertEq(stakerRewards.NETWORK(), tanssi);
        assertEq(stakerRewards.VAULT(), address(vault));
        assertEq(stakerRewards.i_vaultFactory(), address(vaultFactory));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(stakerRewards.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(stakerRewards.i_startTime(), middleware.getEpochStart(0));
        assertEq(stakerRewards.s_adminFee(), ADMIN_FEE);
    }

    function _distributeRewards(uint48 epoch, uint48 eraIndex, uint256 amount, address _token) public {
        vm.startPrank(address(middleware));
        operatorRewards.distributeRewards(epoch, eraIndex, amount, amount, REWARDS_ROOT, address(_token));
        vm.stopPrank();
    }

    function _generateValidProof() internal pure returns (bytes32[] memory) {
        bytes32[] memory proof = new bytes32[](1);
        // Create a valid proof that matches the root we set
        proof[0] = 0x27e610a11a547f210646001377ae223bc6bce387931f8153624d21f6478512d2;
        return proof;
    }

    function _mockVaultActiveSharesStakeAt(uint48 epoch, bool mockShares, bool mockStake) private {
        uint48 epochTs = middleware.getEpochStart(epoch);
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

    function _mockGetOperatorVaults(
        uint48 epoch
    ) private {
        uint48 epochStartTs = middleware.getEpochStart(epoch);

        address[] memory vaults = new address[](1);
        vaults[0] = address(vault);
        vm.mockCall(
            address(middleware),
            abi.encodeWithSelector(IMiddleware.getOperatorVaults.selector, alice, epochStartTs),
            abi.encode(1, vaults)
        );
    }

    function _setSRewardsMapping(uint48 epoch, bool multipleRewards, address newToken) private {
        // For s_rewards[epoch][tokenAddress] = [10 ether]

        // Get base slot for first mapping
        bytes32 slot = keccak256(abi.encode(epoch, uint256(3)));

        // Get slot for second mapping with tokenAddress
        bytes32 tokenSlot = keccak256(abi.encode(address(token), slot));

        // Store array length
        vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(1)));

        // Store array value
        bytes32 arrayLoc = keccak256(abi.encode(tokenSlot));
        vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(10 ether)));

        if (multipleRewards) {
            // Get slot for second mapping with tokenAddress
            tokenSlot = keccak256(abi.encode(address(newToken), slot));

            // Store array length
            vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(1)));

            // Store array value
            arrayLoc = keccak256(abi.encode(tokenSlot));
            vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(10 ether)));
        }
    }

    function _setActiveSharesCache(uint48 epoch, address _stakerRewards) private {
        bytes32 slot = keccak256(abi.encode(epoch, uint256(6))); // 6 is mapping slot number for the variable _s_activeSharesCache
        vm.store(address(_stakerRewards), slot, bytes32(uint256(AMOUNT_TO_DISTRIBUTE / 10)));
    }

    function _setClaimableAdminFee(uint48 epoch, address _token) private {
        // For s_claimableAdminFee[epoch][tokenAddress]

        // Get base slot for first mapping
        bytes32 slot = keccak256(abi.encode(epoch, uint256(5))); // For s_claimableAdminFee mapping at slot 4

        // Get final slot with tokenAddress
        bytes32 finalSlot = keccak256(abi.encode(_token, slot));

        // Store value
        vm.store(address(stakerRewards), finalSlot, bytes32(uint256(10 ether)));
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
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        IODefaultOperatorRewards.EraRoot memory eraRoot_ = operatorRewards.eraRoot(0);
        assertEq(eraRoot_.epoch, epoch);
        assertEq(eraRoot_.amount, AMOUNT_TO_DISTRIBUTE);
        assertEq(eraRoot_.tokensPerPoint, TOKENS_PER_POINT);
        assertEq(eraRoot_.root, REWARDS_ROOT);
        assertEq(eraRoot_.tokenAddress, address(token));

        uint48 eraIndex_ = operatorRewards.eraIndexesPerEpoch(epoch, 0);
        assertEq(eraIndex_, eraIndex);
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
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
    }

    function testDistributeRewardsFailsWhenIsNotMiddleware() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.distributeRewards(
            epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT, address(token)
        );
    }

    function testDistributeRewardsFailsWhenTokenFeeAmountResultInZeroAmount() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        operatorRewards = ODefaultOperatorRewards(
            deployRewards.deployOperatorRewardsContract(
                tanssi, address(networkMiddlewareService), OPERATOR_SHARE, owner
            )
        );
        vm.startPrank(address(middleware));
        feeToken.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTransfer.selector);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(feeToken));
    }

    function testDistributeRewardsFailsWithInvalidTotalPoints() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(tanssi);
        token.transfer(address(middleware), token.balanceOf(tanssi));

        vm.startPrank(address(middleware));
        token.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidTotalPoints.selector);
        operatorRewards.distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, 0, REWARDS_ROOT, address(token));
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimRewards() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        address recipient = Middleware(middleware).operatorByKey(abi.encode(ALICE_KEY));
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
            tanssi, address(token), eraIndex, epoch, (EXPECTED_CLAIMABLE * 80) / 100, REWARDS_ADDITIONAL_DATA
        );
        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.ClaimRewards(
            recipient, address(token), eraIndex, epoch, address(this), EXPECTED_CLAIMABLE
        );
        operatorRewards.claimRewards(claimRewardsData);

        uint256 amountClaimed_ = operatorRewards.claimed(eraIndex, alice);
        assertEq(amountClaimed_, EXPECTED_CLAIMABLE);
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
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
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
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

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

        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

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
        _mockVaultActiveSharesStakeAt(epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
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
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

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
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
        _mockGetOperatorVaults(epoch);
        _mockVaultActiveSharesStakeAt(epoch, true, false);

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
        assertEq(operatorRewards.operatorShare(), newOperatorShare);
    }

    function testSetOperatorShareNotNetworkMiddleware() public {
        uint48 newOperatorShare = 30;
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NotNetworkMiddleware.selector);
        operatorRewards.setOperatorShare(newOperatorShare);
    }

    function testSetOperatorShareInvalidOperatorShare() public {
        uint48 newOperatorShare = 10_000;
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
        assertEq(operatorRewards.vaultToStakerRewardsContract(newVault), newStakerRewards);
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
    //                                          getEpochStart
    //**************************************************************************************************

    function testGetEpochStartTs() public view {
        uint48 epoch = 0;
        uint48 epochStartTs = middleware.getEpochStart(epoch);
        assertEq(stakerRewards.getEpochStartTs(epoch), epochStartTs);
    }

    //**************************************************************************************************
    //                                          rewardsLength
    //**************************************************************************************************

    function testRewardsLength() public {
        uint48 epoch = 0;
        _setSRewardsMapping(epoch, false, address(0));
        uint256 rewardsLength = stakerRewards.rewardsLength(epoch, address(token));
        assertEq(rewardsLength, 1);
    }

    //**************************************************************************************************
    //                                            claimable
    //**************************************************************************************************

    function testClaimable() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);
        _setSRewardsMapping(epoch, false, address(0));

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, uint256(10), address(token));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddress() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setSRewardsMapping(epoch, false, address(0));

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, uint256(10), address(token));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddressButMultipleRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);
        Token newToken = new Token("NewToken");

        _setSRewardsMapping(epoch, true, address(newToken));

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, uint256(10), address(newToken));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************

    function testStakerDistributeRewardsInsufficientReward() public {
        uint48 epoch = 0;
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

        _setActiveSharesCache(epoch, address(newStakerRewards));

        vm.startPrank(address(operatorRewards));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientReward.selector);
        newStakerRewards.distributeRewards(epoch, eraIndex, AMOUNT_TO_CLAIM, address(feeToken), REWARDS_ADDITIONAL_DATA);
    }

    function testStakerDistributeRewardsWrongRole() public {
        uint48 epoch = 0;
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

        bytes32 operatoRewardsRoleHolder = stakerRewards.OPERATOR_REWARDS_ROLE();

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.startPrank(address(middleware));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(middleware), operatoRewardsRoleHolder
            )
        );
        newStakerRewards.distributeRewards(epoch, eraIndex, AMOUNT_TO_CLAIM, address(token), REWARDS_ADDITIONAL_DATA);
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimStakerRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setSRewardsMapping(epoch, false, address(0));

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(
            tanssi, address(token), alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10
        );
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setSRewardsMapping(epoch, false, address(0));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(
            tanssi, address(token), alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10
        );
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroAmount() public {
        uint48 epoch = 0;

        _setSRewardsMapping(epoch, false, address(0));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, address(token), alice, epoch, alice, 0, 1, 0);
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidRecipient() public {
        uint48 epoch = 0;

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidRecipient.selector);
        stakerRewards.claimRewards(address(0), epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsNoRewardsToClaim() public {
        uint48 epoch = 0;

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsInvalidHintsLength() public {
        uint48 epoch = 0;

        _setSRewardsMapping(epoch, false, address(0));

        // 2 (fake) hints, but the reward set is only 1
        bytes memory claimRewardsWithMismatchingHintsLength =
            hex"0000000000000000000000000000000000000000000000056bc75e2d6310000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf60000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";
        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidHintsLength.selector);
        stakerRewards.claimRewards(alice, epoch, address(token), claimRewardsWithMismatchingHintsLength);
    }

    function testClaimStakerRewardsWithFakeHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setSRewardsMapping(epoch, false, address(0));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

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
        bytes memory claimRewardsWithFakeHints =
            hex"0000000000000000000000000000000000000000000000056bc75e2d631000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000020b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(
            tanssi, address(token), alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10
        );
        stakerRewards.claimRewards(alice, epoch, address(token), claimRewardsWithFakeHints);
    }

    function testClaimStakerRewardsButWithFakeTokenAddressNoRewardsToClaim() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setSRewardsMapping(epoch, false, address(0));
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, epoch, address(1), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsButMultipleRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);
        Token newToken = new Token("NewToken");
        newToken.transfer(address(middleware), AMOUNT_TO_DISTRIBUTE);

        _setSRewardsMapping(epoch, true, address(newToken));
        vm.prank(address(middleware));
        newToken.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards));

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(
            tanssi, address(newToken), alice, epoch, alice, 0, 1, AMOUNT_TO_DISTRIBUTE / 10
        );
        stakerRewards.claimRewards(alice, epoch, address(newToken), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    //**************************************************************************************************
    //                                      setAdminFee
    //**************************************************************************************************

    function testSetAdminFee() public {
        uint256 newFee = ADMIN_FEE + 100;
        vm.startPrank(address(tanssi));
        vm.expectEmit(true, false, false, true);
        emit IODefaultStakerRewards.SetAdminFee(newFee);
        stakerRewards.setAdminFee(newFee);
        assertEq(stakerRewards.s_adminFee(), newFee);
    }

    function testSetAdminFeeAlreadySet() public {
        uint256 newFee = ADMIN_FEE;
        vm.startPrank(address(tanssi));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__AlreadySet.selector);
        stakerRewards.setAdminFee(newFee);
    }

    function testSetAdminFeeInvalidAdminFee() public {
        uint256 newFee = stakerRewards.ADMIN_FEE_BASE() + 1;
        vm.startPrank(address(tanssi));
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
        _setClaimableAdminFee(epoch, address(token));

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), 10 ether);

        vm.startPrank(address(tanssi));
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.ClaimAdminFee(tanssi, address(token), 10 ether);
        stakerRewards.claimAdminFee(tanssi, epoch, address(token));
    }

    function testClaimAdminFeeInsufficientAdminFee() public {
        uint48 epoch = 0;

        vm.startPrank(address(tanssi));
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientAdminFee.selector);
        stakerRewards.claimAdminFee(tanssi, epoch, address(token));
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
        stakerRewards.claimAdminFee(tanssi, epoch, address(token));
    }

    //**************************************************************************************************
    //                                      UPGRADING
    //**************************************************************************************************

    function testUpgrade() public {
        vm.startPrank(address(middleware));
        address mockStakerRewards = makeAddr("mockStakerRewards");
        address mockVault = makeAddr("mockVault");

        operatorRewards.setStakerRewardContract(mockStakerRewards, mockVault);

        vm.startPrank(address(owner));
        ODefaultOperatorRewards newOperatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService));
        operatorRewards.upgradeToAndCall(address(newOperatorRewards), hex"");

        assertEq(operatorRewards.vaultToStakerRewardsContract(mockVault), mockStakerRewards);
        assertEq(operatorRewards.operatorShare(), OPERATOR_SHARE);
    }

    function testUpgradeNotAuthorized() public {
        ODefaultOperatorRewards newOperatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService));

        address randomUser = makeAddr("randomUser");
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, randomUser));
        operatorRewards.upgradeToAndCall(address(newOperatorRewards), hex"");
    }
}
