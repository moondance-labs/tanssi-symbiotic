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
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
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
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";

import {DelegatorMock} from "../mocks/symbiotic/DelegatorMock.sol";
import {OptInServiceMock} from "../mocks/symbiotic/OptInServiceMock.sol";
import {RegistryMock} from "../mocks/symbiotic/RegistryMock.sol";
import {VaultMock} from "../mocks/symbiotic/VaultMock.sol";
import {Token} from "../mocks/Token.sol";
import {MockFeeToken} from "../mocks/FeeToken.sol";

import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";

contract RewardsTest is Test {
    using Math for uint48;

    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant AMOUNT_TO_DISTRIBUTE = 100 ether;
    uint256 public constant DEFAULT_AMOUNT = AMOUNT_TO_DISTRIBUTE / 10;
    uint32 public constant POINTS_TO_CLAIM = 20;
    uint256 public constant TOKENS_PER_POINT = 1;
    uint256 public constant EXPECTED_CLAIMABLE = uint256(POINTS_TO_CLAIM) * TOKENS_PER_POINT;
    uint256 public constant ADMIN_FEE = 800; // 8%
    uint48 public constant OPERATOR_SHARE = 2000;
    uint8 public constant ORACLE_DECIMALS = 18;
    int256 public constant ORACLE_CONVERSION_TOKEN = 3000;

    // Root hash of the rewards merkle tree. It represents the rewards for the epoch 0 for alice and bob with 20 points each
    bytes32 public constant REWARDS_ROOT = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;
    bytes32 public constant STAKER_REWARDS_STORAGE_LOCATION =
        0xef473712465551821e7a51c85c06a1bf76bdf2a3508e28184170ac7eb0322c00;
    bytes32 private constant PREVIOUS_STAKER_REWARDS_STORAGE_LOCATION =
        0xe07cde22a6017f26eee680b6867ce6727151fb6097c75742cbe379265c377400;
    bytes32 public constant MIDDLEWARE_STORAGE_LOCATION =
        0xca64b196a0d05040904d062f739ed1d1e1d3cc5de78f7001fb9039595fce9100;

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
    DeployCollateral deployCollateral;

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
        address readHelper = address(new OBaseMiddlewareReader());

        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        deployCollateral = new DeployCollateral();
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

        token = new Token("Token", 18);
        MockV3Aggregator collateralOracle = new MockV3Aggregator(ORACLE_DECIMALS, ORACLE_CONVERSION_TOKEN);

        vault = new VaultMock(delegatorFactory, slasherFactory, address(vaultFactory), address(token));
        vault.setDelegator(address(delegator));
        vm.store(address(delegator), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        vm.mockCall(
            address(vaultFactory), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), operatorRewardsAddress, tanssi
        );
        stakerRewardsFactory = ODefaultStakerRewardsFactory(stakerRewardsFactoryAddress);

        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(tanssi),
            adminFeeClaimRoleHolder: address(tanssi),
            adminFeeSetRoleHolder: address(tanssi)
        });
        stakerRewards = ODefaultStakerRewards(stakerRewardsFactory.create(address(vault), stakerRewardsParams));

        Middleware _middlewareImpl = new Middleware(operatorRewardsAddress, address(stakerRewards));
        middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
        vm.startPrank(owner);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware));
        vm.stopPrank();
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(operatorRegistry),
            vaultRegistry: address(vaultFactory),
            operatorNetworkOptIn: address(operatorNetworkOptIn),
            owner: tanssi,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper
        });
        Middleware(address(middleware)).initialize(params);

        vm.prank(owner);

        slasher = new Slasher(address(vaultFactory), address(networkMiddlewareService), slasherFactory, 0);

        token.transfer(address(middleware), token.totalSupply());

        vm.startPrank(tanssi);
        middleware.setCollateralToOracle(address(token), address(collateralOracle));
        networkRegistry.registerNetwork();
        networkMiddlewareService.setMiddleware(address(middleware));

        _setVaultToCollateral(address(vault), address(token));

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

        vm.stopPrank();
    }

    function testConstructors() public view {
        assertEq(operatorRewards.i_network(), tanssi);
        assertEq(operatorRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(operatorRewards.vaultToStakerRewardsContract(address(vault)), address(stakerRewards));
        assertEq(operatorRewards.operatorShare(), OPERATOR_SHARE);

        assertEq(stakerRewards.i_network(), tanssi);
        assertEq(stakerRewards.i_vault(), address(vault));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
        assertEq(stakerRewards.adminFee(), ADMIN_FEE);
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

    function _mockVaultActiveSharesStakeAt(address vault_, uint48 epoch, bool mockShares, bool mockStake) private {
        uint48 epochTs = middleware.getEpochStart(epoch);
        (, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(REWARDS_ADDITIONAL_DATA, (uint256, bytes, bytes));

        if (mockShares) {
            vm.mockCall(
                vault_,
                abi.encodeWithSelector(IVaultStorage.activeSharesAt.selector, epochTs, activeSharesHint),
                abi.encode(AMOUNT_TO_DISTRIBUTE)
            );
        }
        if (mockStake) {
            vm.mockCall(
                vault_,
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
            abi.encodeWithSelector(OBaseMiddlewareReader.getOperatorVaults.selector, alice, epochStartTs),
            abi.encode(1, vaults)
        );
    }

    function _setPreviousRewardsMapping(uint48 epoch, bool multipleRewards, address newToken, uint256 amount) private {
        // For StakerRewardsStorage.rewards[epoch][tokenAddress] = [10 ether]

        // Get base slot for first mapping
        bytes32 slot = bytes32(uint256(PREVIOUS_STAKER_REWARDS_STORAGE_LOCATION) + uint256(1)); // 1 is mapping slot number for the variable rewards
        slot = keccak256(abi.encode(epoch, slot));
        // Get slot for second mapping with tokenAddress
        bytes32 tokenSlot = keccak256(abi.encode(address(token), slot));

        // Store array length
        vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(1)));

        // Store array value
        bytes32 arrayLoc = keccak256(abi.encode(tokenSlot));
        vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(amount)));

        if (multipleRewards && newToken != address(0)) {
            // Get slot for second mapping with tokenAddress
            tokenSlot = keccak256(abi.encode(newToken, slot));

            // Store array length
            vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(1)));

            // Store array value
            arrayLoc = keccak256(abi.encode(tokenSlot));
            vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(amount)));
        } else if (multipleRewards) {
            // Store array length
            vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(2)));

            arrayLoc = keccak256(abi.encode(tokenSlot));
            vm.store(address(stakerRewards), arrayLoc, bytes32(uint256(amount)));

            // Store second reward at index 1 (arrayLoc + 1)
            vm.store(address(stakerRewards), bytes32(uint256(arrayLoc) + 1), bytes32(uint256(amount)));
        }
    }

    function _setVaultToCollateral(address vault_, address collateral_) internal {
        bytes32 slot = bytes32(uint256(MIDDLEWARE_STORAGE_LOCATION) + uint256(5)); // 5 is mapping slot number for the vault to collateral
        // Get slot for mapping with vault_
        slot = keccak256(abi.encode(vault_, slot));

        // Store array length
        vm.store(address(middleware), slot, bytes32(uint256(uint160(collateral_))));
    }

    function _setRewardsMapping(
        uint48 epoch,
        uint256 additionalRewards,
        address newToken,
        bytes32 location,
        uint256 amount
    ) private {
        // For StakerRewardsStorage.rewards[epoch][tokenAddress] = [10 ether]

        // Get base slot for first mapping
        bytes32 slot = bytes32(uint256(location) + uint256(1)); // 1 is mapping slot number for the variable rewards
        slot = keccak256(abi.encode(epoch, slot));
        // Get slot for second mapping with tokenAddress
        bytes32 tokenSlot = keccak256(abi.encode(address(token), slot));

        vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(amount)));

        if (additionalRewards != 0) {
            // Get slot for second mapping with tokenAddress
            tokenSlot = keccak256(abi.encode(address(newToken), slot));

            vm.store(address(stakerRewards), tokenSlot, bytes32(uint256(additionalRewards)));
        }
    }

    function _setActiveSharesCache(uint48 epoch, address _stakerRewards, bytes32 location, uint256 amount) private {
        // For StakerRewardsStorage.activeSharesCache[epoch] = AMOUNT_TO_DISTRIBUTE / 10
        bytes32 slot = bytes32(uint256(location) + uint256(4)); // 4 is mapping slot number for the variable activeSharesCache
        slot = keccak256(abi.encode(epoch, slot));
        vm.store(address(_stakerRewards), slot, bytes32(amount));
    }

    function _setLastUnclaimedReward(uint48 epoch, address account, address _stakerRewards, uint256 index) private {
        bytes32 slot = bytes32(uint256(PREVIOUS_STAKER_REWARDS_STORAGE_LOCATION) + uint256(2)); // 2 is mapping slot number for the variable lastUnclaimedReward
        slot = keccak256(abi.encode(account, slot));
        slot = keccak256(abi.encode(epoch, slot));
        slot = keccak256(abi.encode(address(token), slot));
        vm.store(address(_stakerRewards), slot, bytes32(index));
    }

    function _setClaimableAdminFee(uint48 epoch, address _token, bytes32 location, uint256 amount) private {
        // For StakerRewardsStorage.claimableAdminFee[epoch][tokenAddress] = 10 ether
        bytes32 slot = bytes32(uint256(location) + uint256(3)); // 3 is slot number for the variable claimableAdminFee
        slot = keccak256(abi.encode(epoch, slot));
        slot = keccak256(abi.encode(_token, slot));
        vm.store(address(stakerRewards), slot, bytes32(amount));
    }

    //**************************************************************************************************
    //                                      ODefaultStakerRewards
    //**************************************************************************************************

    function testCreateStakerRewardsWithNoNetwork() public {
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAddress.selector);
        stakerRewards = new ODefaultStakerRewards(
            address(networkMiddlewareService), // networkMiddlewareService
            address(vault), // vault
            address(0) // network
        );
    }

    function testCreateStakerRewardsWithNoNetworkMiddlewareService() public {
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAddress.selector);
        stakerRewards = new ODefaultStakerRewards(
            address(0), // networkMiddlewareService
            address(vault), // vault
            tanssi // network
        );
    }

    function testCreateStakerRewardsWithNoVault() public {
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAddress.selector);
        stakerRewards = new ODefaultStakerRewards(
            address(networkMiddlewareService), // networkMiddlewareService
            address(0), // vault
            tanssi // network
        );
    }

    function testInitializeStakerRewardsWithNoOperatorRewards() public {
        stakerRewards = new ODefaultStakerRewards(
            address(networkMiddlewareService), // networkMiddlewareService
            address(vault), // vault
            tanssi // network
        );

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });
        address proxy = address(new ERC1967Proxy((address(stakerRewards)), ""));

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAddress.selector);
        ODefaultStakerRewards(proxy).initialize(address(0), params);
    }

    //**************************************************************************************************
    //                                      ODefaultOperatorRewards
    //**************************************************************************************************

    function testCreateOperatorRewardsWithNoNetwork() public {
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        operatorRewards = new ODefaultOperatorRewards(
            address(0), // network
            address(networkMiddlewareService) // networkMiddlewareService
        );
    }

    function testCreateOperatorRewardsWithNoNetworkMiddleware() public {
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        operatorRewards = new ODefaultOperatorRewards(
            tanssi, // network
            address(0) // networkMiddlewareService
        );
    }

    function testInitializeOperatorRewardsWithNoOwner() public {
        operatorRewards = new ODefaultOperatorRewards(
            tanssi, // network
            address(networkMiddlewareService) // networkMiddlewareService
        );
        address proxy = address(new ERC1967Proxy((address(operatorRewards)), ""));

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        ODefaultOperatorRewards(proxy).initialize(0, address(0));
    }

    function testInitializeOperatorRewardsWithTooBigShares() public {
        operatorRewards = new ODefaultOperatorRewards(
            tanssi, // network
            address(networkMiddlewareService) // networkMiddlewareService
        );
        address proxy = address(new ERC1967Proxy((address(operatorRewards)), ""));
        uint48 MAX_PERCENTAGE = operatorRewards.MAX_PERCENTAGE();
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidOperatorShare.selector);
        ODefaultOperatorRewards(proxy).initialize(MAX_PERCENTAGE + 1, address(networkMiddlewareService));
    }

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
            epoch, eraIndex, address(token), AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT
        );
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        IODefaultOperatorRewards.EraRoot memory eraRoot_ = operatorRewards.eraRoot(0);
        assertEq(eraRoot_.epoch, epoch);
        assertEq(eraRoot_.amount, AMOUNT_TO_DISTRIBUTE);
        assertEq(eraRoot_.totalPoints, AMOUNT_TO_DISTRIBUTE);
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

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(this),
                operatorRewards.MIDDLEWARE_ROLE()
            )
        );
        operatorRewards.distributeRewards(
            epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT, address(token)
        );
    }

    function testDistributeRewardsFailsWhenTokenFeeAmountResultInZeroAmount() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(address(middleware));
        feeToken.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InsufficientTransfer.selector);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(feeToken));
    }

    function testDistributeRewardsFailsWithInvalidTotalPoints() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(address(middleware));
        token.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidValues.selector);
        operatorRewards.distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, 0, REWARDS_ROOT, address(token));
    }

    function testDistributeRewardsFailsWithInvalidAmount() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.startPrank(address(middleware));
        token.approve(address(operatorRewards), type(uint256).max);
        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidValues.selector);
        operatorRewards.distributeRewards(epoch, eraIndex, 0, AMOUNT_TO_DISTRIBUTE, REWARDS_ROOT, address(token));
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimRewards() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(address(vault), epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        address recipient = Middleware(middleware).operatorByKey(abi.encode(ALICE_KEY));
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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

        uint256 amountClaimed_ = operatorRewards.claimed(eraIndex, abi.encode(ALICE_KEY));
        assertEq(amountClaimed_, EXPECTED_CLAIMABLE);
    }

    function testClaimRewardsWithMultipleVaults() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;
        uint48 epochStartTs = middleware.getEpochStart(epoch);
        address[] memory vaults = new address[](2);
        vaults[0] = address(vault);
        vaults[1] = makeAddr("vault2");

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(vaults[0], epoch, true, true);
        _mockVaultActiveSharesStakeAt(vaults[1], epoch, true, true);

        vm.mockCall(
            address(middleware),
            abi.encodeWithSelector(IOBaseMiddlewareReader.getOperatorVaults.selector, alice, epochStartTs),
            abi.encode(2, vaults)
        );

        // The method has 3 implementations so we need to get the selector manually
        bytes4 selector = bytes4(keccak256("getOperatorPowerAt(uint48,address,address,uint96)"));
        vm.mockCall(
            address(middleware), abi.encodeWithSelector(selector, epochStartTs, alice, vaults[0], 0), abi.encode(40)
        );
        vm.mockCall(
            address(middleware), abi.encodeWithSelector(selector, epochStartTs, alice, vaults[1], 0), abi.encode(60)
        );

        address stakerRewards2 = makeAddr("newStakerRewards");
        vm.startPrank(address(middleware));
        operatorRewards.setStakerRewardContract(stakerRewards2, vaults[1]);
        vm.mockCall(
            stakerRewards2,
            abi.encodeWithSelector(
                IODefaultStakerRewards.distributeRewards.selector,
                epoch,
                eraIndex,
                1000,
                address(token),
                REWARDS_ADDITIONAL_DATA
            ),
            abi.encode()
        );

        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        address recipient = Middleware(middleware).operatorByKey(abi.encode(ALICE_KEY));
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        // 40% of the staker rewards are distributed to the first vault. Order is important due to rounding.
        uint256 expectedAmountStakers = (EXPECTED_CLAIMABLE * 80) / 100;
        uint256 expectedAmountVault1 = (expectedAmountStakers * 40) / 100; // 100 here is total power of operator: 40 + 60
        uint256 expectedAmountVault2 = expectedAmountStakers - expectedAmountVault1;
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.DistributeRewards(
            tanssi, address(token), eraIndex, epoch, expectedAmountVault1, REWARDS_ADDITIONAL_DATA
        );

        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.ClaimRewards(
            recipient, address(token), eraIndex, epoch, address(this), EXPECTED_CLAIMABLE
        );

        {
            uint256 gasBefore = gasleft();
            operatorRewards.claimRewards(claimRewardsData);
            uint256 gasAfter = gasleft();

            uint256 gasClaiming = gasBefore - gasAfter;
            console2.log("Total gas used: ", gasClaiming);
        }

        uint256 amountClaimed_ = operatorRewards.claimed(eraIndex, abi.encode(ALICE_KEY));
        assertEq(amountClaimed_, EXPECTED_CLAIMABLE);

        uint256 stakerRewardsVault1Balance = token.balanceOf(address(stakerRewards));
        assertEq(stakerRewardsVault1Balance, expectedAmountVault1);

        // StakerRewards2 is a mock so it would not take the balance, but it should have the right allowance
        uint256 stakerRewardsVault2Allowance = token.allowance(address(operatorRewards), address(stakerRewards2));
        assertEq(stakerRewardsVault2Allowance, expectedAmountVault2);
    }

    function testClaimRewardsWithNoVaults() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;
        uint48 epochStartTs = middleware.getEpochStart(epoch);
        vm.mockCall(
            address(middleware),
            abi.encodeWithSelector(IOBaseMiddlewareReader.getOperatorVaults.selector, alice, epochStartTs),
            abi.encode(0, new address[](0))
        );

        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__NoVaults.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsRootNotSet() public {
        uint48 eraIndex = 0;
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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
            totalPointsClaimable: POINTS_TO_CLAIM,
            proof: proof,
            data: REWARDS_ADDITIONAL_DATA
        });
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testClaimRewardsWhenInsufficientTotalClaimable() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;

        vm.warp(NETWORK_EPOCH_DURATION);
        _mockVaultActiveSharesStakeAt(address(vault), epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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

        _mockVaultActiveSharesStakeAt(address(vault), epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));

        bytes32[] memory proof = _generateValidProof();
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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
        _mockVaultActiveSharesStakeAt(address(vault), epoch, true, true);
        _mockGetOperatorVaults(epoch);
        _distributeRewards(epoch, eraIndex, AMOUNT_TO_DISTRIBUTE, address(token));
        bytes memory rewardsDataWithHighAdminFee =
            hex"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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
            totalPointsClaimable: POINTS_TO_CLAIM,
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
        _mockVaultActiveSharesStakeAt(address(vault), epoch, true, false);

        bytes32[] memory proof = _generateValidProof();

        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: ALICE_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: POINTS_TO_CLAIM,
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(this),
                operatorRewards.MIDDLEWARE_ROLE()
            )
        );
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
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(this),
                operatorRewards.STAKER_REWARDS_SETTER_ROLE()
            )
        );
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
    //                                      ODefaultStakerRewardsFactory
    //**************************************************************************************************

    //**************************************************************************************************
    //                                          constructor
    //**************************************************************************************************

    function testStakerRewardsFactoryConstructorNoVaultFactory() public {
        vm.expectRevert(IODefaultStakerRewardsFactory.ODefaultStakerRewardsFactory__InvalidAddress.selector);
        deployRewards.deployStakerRewardsFactoryContract(
            address(0), address(networkMiddlewareService), address(operatorRewards), tanssi
        );
    }

    function testStakerRewardsFactoryConstructorNoNetworkMiddlewareService() public {
        vm.expectRevert(IODefaultStakerRewardsFactory.ODefaultStakerRewardsFactory__InvalidAddress.selector);
        deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(0), address(operatorRewards), tanssi
        );
    }

    function testStakerRewardsFactoryConstructorNoOperatorRewards() public {
        vm.expectRevert(IODefaultStakerRewardsFactory.ODefaultStakerRewardsFactory__InvalidAddress.selector);
        deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), address(0), tanssi
        );
    }

    function testStakerRewardsFactoryConstructorNoNetwork() public {
        vm.expectRevert(IODefaultStakerRewardsFactory.ODefaultStakerRewardsFactory__InvalidAddress.selector);
        deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), address(operatorRewards), address(0)
        );
    }

    //**************************************************************************************************
    //                                      ODefaultStakerRewards
    //**************************************************************************************************

    //**************************************************************************************************
    //                                          constructor
    //**************************************************************************************************

    function testStakerRewardsFactoryConstructorNotVault() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
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

        vm.expectRevert(IODefaultStakerRewardsFactory.ODefaultStakerRewardsFactory__NotVault.selector);
        stakerRewardsFactory.create(address(vault), params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndNoAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(address(vault), params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeAndBothAdminRole() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        IODefaultStakerRewards newStakerRewards =
            IODefaultStakerRewards(stakerRewardsFactory.create(address(vault), params));

        assertEq(newStakerRewards.adminFee(), 0);
    }

    function testStakerRewardsConstructorWithInvalidAdminFee() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: stakerRewards.ADMIN_FEE_BASE() + 1,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InvalidAdminFee.selector);
        stakerRewardsFactory.create(address(vault), params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeSetRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(0)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(address(vault), params);
    }

    function testStakerRewardsConstructorWithNoAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(0),
            adminFeeSetRoleHolder: address(middleware)
        });

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__MissingRoles.selector);
        stakerRewardsFactory.create(address(vault), params);
    }

    function testStakerRewardsConstructorWithAdminFeeClaimRoleHolder() public {
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(0),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });

        IODefaultStakerRewards newStakerRewards =
            IODefaultStakerRewards(stakerRewardsFactory.create(address(vault), params));

        assertEq(newStakerRewards.adminFee(), ADMIN_FEE);
    }

    //**************************************************************************************************
    //                                          stakerClaimedRewardPerEpoch
    //**************************************************************************************************

    function testStakerClaimedRewardPerEpoch() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);

        uint256 stakerClaimed = stakerRewards.stakerClaimedRewardPerEpoch(alice, epoch, address(token));
        assertEq(stakerClaimed, AMOUNT_TO_DISTRIBUTE / 10);
    }

    //**************************************************************************************************
    //                                            claimable
    //**************************************************************************************************

    function testClaimable() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);
        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, address(token));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddress() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, address(token));
        assertEq(claimable, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimableButWithFakeTokenAddressButMultipleRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);
        Token newToken = new Token("NewToken", 18);
        uint256 newTokenRewardsAmount = 20 ether;

        _setRewardsMapping(
            epoch, newTokenRewardsAmount, address(newToken), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT
        );

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        uint256 claimable = stakerRewards.claimable(epoch, alice, address(newToken));
        assertEq(claimable, newTokenRewardsAmount);
    }

    //**************************************************************************************************
    //                                      distributeRewards
    //**************************************************************************************************

    function testStakerDistributeRewardsInsufficientReward() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;
        vm.warp(NETWORK_EPOCH_DURATION);
        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });
        IODefaultStakerRewards newStakerRewards =
            IODefaultStakerRewards(stakerRewardsFactory.create(address(vault), params));

        _setActiveSharesCache(epoch, address(newStakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.startPrank(address(operatorRewards));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__InsufficientReward.selector);
        newStakerRewards.distributeRewards(epoch, eraIndex, POINTS_TO_CLAIM, address(feeToken), REWARDS_ADDITIONAL_DATA);
    }

    function testStakerDistributeRewardsWrongRole() public {
        uint48 epoch = 0;
        uint48 eraIndex = 0;
        vm.warp(NETWORK_EPOCH_DURATION);

        IODefaultStakerRewards.InitParams memory params = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: address(middleware),
            adminFeeClaimRoleHolder: address(middleware),
            adminFeeSetRoleHolder: address(middleware)
        });
        IODefaultStakerRewards newStakerRewards =
            IODefaultStakerRewards(stakerRewardsFactory.create(address(vault), params));

        bytes32 operatoRewardsRoleHolder = stakerRewards.OPERATOR_REWARDS_ROLE();

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.startPrank(address(middleware));
        feeToken.approve(address(newStakerRewards), type(uint256).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(middleware), operatoRewardsRoleHolder
            )
        );
        newStakerRewards.distributeRewards(epoch, eraIndex, POINTS_TO_CLAIM, address(token), REWARDS_ADDITIONAL_DATA);
    }

    //**************************************************************************************************
    //                                      claimRewards
    //**************************************************************************************************

    function testClaimStakerRewards() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        uint256 pendingRewards = stakerRewards.rewards(epoch, address(token));
        assertEq(pendingRewards, 10 ether);

        uint256 claimed = stakerRewards.stakerClaimedRewardPerEpoch(alice, epoch, address(token));
        assertEq(claimed, 0);

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, address(token), alice, epoch, alice, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);

        claimed = stakerRewards.stakerClaimedRewardPerEpoch(alice, epoch, address(token));
        assertEq(claimed, AMOUNT_TO_DISTRIBUTE / 10);
    }

    function testClaimStakerRewardsWithZeroHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, address(token), alice, epoch, alice, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, address(token), CLAIM_REWARDS_ADDITIONAL_DATA);
    }

    function testClaimStakerRewardsWithZeroAmount() public {
        uint48 epoch = 0;

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.prank(alice);
        vm.expectRevert(IODefaultStakerRewards.ODefaultStakerRewards__NoRewardsToClaim.selector);
        stakerRewards.claimRewards(alice, epoch, address(token), hex"");
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

    function testClaimStakerRewardsWithFakeHints() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

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
        bytes memory claimRewardsWithFakeHints = hex"b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6";

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, address(token), alice, epoch, alice, AMOUNT_TO_DISTRIBUTE / 10);
        stakerRewards.claimRewards(alice, epoch, address(token), claimRewardsWithFakeHints);
    }

    function testClaimStakerRewardsButWithFakeTokenAddressNoRewardsToClaim() public {
        uint48 epoch = 0;
        uint48 epochTs = middleware.getEpochStart(epoch);

        _setRewardsMapping(epoch, 0, address(0), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);
        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), AMOUNT_TO_DISTRIBUTE / 10);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

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
        Token newToken = new Token("NewToken", 18);
        newToken.transfer(address(middleware), AMOUNT_TO_DISTRIBUTE);
        uint256 newTokenAmountRewards = 20 ether;

        _setRewardsMapping(
            epoch, newTokenAmountRewards, address(newToken), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT
        );
        vm.prank(address(middleware));
        newToken.transfer(address(stakerRewards), newTokenAmountRewards);

        _setActiveSharesCache(epoch, address(stakerRewards), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.mockCall(
            address(vault),
            abi.encodeWithSelector(IVaultStorage.activeSharesOfAt.selector, alice, epochTs, hex""),
            abi.encode(AMOUNT_TO_DISTRIBUTE / 10)
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IODefaultStakerRewards.ClaimRewards(tanssi, address(newToken), alice, epoch, alice, newTokenAmountRewards);
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
        assertEq(stakerRewards.adminFee(), newFee);
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
        _setClaimableAdminFee(epoch, address(token), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        uint256 claimableFee = stakerRewards.claimableAdminFee(epoch, address(token));
        assertEq(claimableFee, 10 ether);

        vm.prank(address(middleware));
        token.transfer(address(stakerRewards), 10 ether);

        vm.startPrank(address(tanssi));
        vm.expectEmit(true, true, false, true);
        emit IODefaultStakerRewards.ClaimAdminFee(tanssi, address(token), 10 ether);
        stakerRewards.claimAdminFee(tanssi, epoch, address(token));

        claimableFee = stakerRewards.claimableAdminFee(epoch, address(token));
        assertEq(claimableFee, 0);
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

    function testUpgradeOperatorRewards() public {
        vm.startPrank(address(middleware));
        address mockStakerRewards = makeAddr("mockStakerRewards");
        address mockVault = makeAddr("mockVault");

        operatorRewards.setStakerRewardContract(mockStakerRewards, mockVault);

        deployRewards.upgradeOperatorRewards(address(operatorRewards), owner, address(networkMiddlewareService));

        assertEq(operatorRewards.vaultToStakerRewardsContract(mockVault), mockStakerRewards);
        assertEq(operatorRewards.operatorShare(), OPERATOR_SHARE);
    }

    function testUpgradeOperatorRewardsNotAuthorized() public {
        ODefaultOperatorRewards newOperatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService));
        bytes32 adminRole = newOperatorRewards.DEFAULT_ADMIN_ROLE();
        address randomUser = makeAddr("randomUser");
        vm.prank(randomUser);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, adminRole)
        );
        operatorRewards.upgradeToAndCall(address(newOperatorRewards), hex"");
    }

    function testUpgradeStakerRewards() public {
        uint48 epoch = 0;
        _setClaimableAdminFee(epoch, address(token), STAKER_REWARDS_STORAGE_LOCATION, DEFAULT_AMOUNT);

        vm.startPrank(address(tanssi));
        ODefaultStakerRewards newStakerRewards =
            new ODefaultStakerRewards(address(networkMiddlewareService), address(vault), tanssi);

        stakerRewards.upgradeToAndCall(address(newStakerRewards), hex"");

        assertEq(stakerRewards.i_vault(), address(vault));
        assertEq(stakerRewards.i_network(), tanssi);
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));

        uint256 claimableFee = stakerRewards.claimableAdminFee(epoch, address(token));
        assertEq(claimableFee, 10 ether);
    }

    function testUpgradeStakerRewardsNotAuthorized() public {
        ODefaultStakerRewards newStakerRewards =
            new ODefaultStakerRewards(address(networkMiddlewareService), address(vault), tanssi);
        bytes32 adminRole = stakerRewards.DEFAULT_ADMIN_ROLE();

        address randomUser = makeAddr("randomUser");
        vm.prank(randomUser);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, randomUser, adminRole)
        );
        stakerRewards.upgradeToAndCall(address(newStakerRewards), hex"");
    }

    //**************************************************************************************************
    //                                      UPGRADE
    //**************************************************************************************************

    function testUpgradeAndMigrateStakerRewards() public {
        vm.warp(NETWORK_EPOCH_DURATION);

        deployRewards.upgradeStakerRewards(
            address(stakerRewards), address(networkMiddlewareService), address(vault), address(tanssi)
        );

        assertEq(stakerRewards.i_vault(), address(vault));
        assertEq(stakerRewards.i_network(), address(tanssi));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
    }

    function testUpgradeAndMigrateStakerRewardsWithBroadcast() public {
        vm.startPrank(tanssi);
        // On not testing mode, the owner of the contract to upgrade is this, so we need to grant the admin role to it
        address ownerForUpgrade = vm.addr(deployRewards.ownerPrivateKey());
        stakerRewards.grantRole(stakerRewards.DEFAULT_ADMIN_ROLE(), ownerForUpgrade);
        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION);

        deployRewards.setIsTest(false);
        deployRewards.upgradeStakerRewards(
            address(stakerRewards), address(networkMiddlewareService), address(vault), address(tanssi)
        );

        assertEq(stakerRewards.i_vault(), address(vault));
        assertEq(stakerRewards.i_network(), address(tanssi));
        assertEq(stakerRewards.i_networkMiddlewareService(), address(networkMiddlewareService));
    }
}
