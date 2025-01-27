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
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";

import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {SimpleKeyRegistry32} from "src/contracts/libraries/SimpleKeyRegistry32.sol";

import {DelegatorMock} from "../mocks/symbiotic/DelegatorMock.sol";
import {OptInServiceMock} from "../mocks/symbiotic/OptInServiceMock.sol";
import {RegistryMock} from "../mocks/symbiotic/RegistryMock.sol";
import {VaultMock} from "../mocks/symbiotic/VaultMock.sol";
import {Token} from "../mocks/Token.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;

    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant OPERATOR_STAKE = 10 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;

    uint48 public constant START_TIME = 1;

    address tanssi = makeAddr("tanssi");
    address vaultFactory = makeAddr("vaultFactory");
    address slasherFactory = makeAddr("vaultFactory");
    address delegatorFactory = makeAddr("delegatorFactory");

    address owner = makeAddr("owner");
    address operator = makeAddr("operator");
    NetworkMiddlewareService networkMiddlewareService;
    OptInServiceMock operatorNetworkOptInServiceMock;
    OptInServiceMock operatorVaultOptInServiceMock;
    DelegatorMock delegator;
    Middleware middleware;
    RegistryMock registry;
    VaultMock vault;
    Slasher slasher;
    VetoSlasher vetoSlasher;
    Slasher slasherWithBadType;

    function setUp() public {
        vm.startPrank(owner);

        registry = new RegistryMock();
        operatorNetworkOptInServiceMock =
            new OptInServiceMock(address(registry), address(registry), "OperatorNetworkOptInService");

        operatorVaultOptInServiceMock =
            new OptInServiceMock(address(registry), address(vaultFactory), "OperatorVaultOptInService");

        networkMiddlewareService = new NetworkMiddlewareService(address(registry));

        delegator = new DelegatorMock(
            address(registry),
            vaultFactory,
            address(operatorVaultOptInServiceMock),
            address(operatorNetworkOptInServiceMock),
            delegatorFactory,
            0
        );
        slasher = new Slasher(vaultFactory, address(networkMiddlewareService), slasherFactory, 0);
        slasherWithBadType = new Slasher(vaultFactory, address(networkMiddlewareService), slasherFactory, 2);
        vetoSlasher =
            new VetoSlasher(vaultFactory, address(networkMiddlewareService), address(registry), slasherFactory, 1);

        vault = new VaultMock(delegatorFactory, slasherFactory, vaultFactory);
        vault.setDelegator(address(delegator));

        vm.store(address(delegator), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware = new Middleware(
            address(tanssi),
            address(registry),
            address(registry),
            address(operatorNetworkOptInServiceMock),
            owner,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );

        vm.startPrank(tanssi);
        registry.register();
        networkMiddlewareService.setMiddleware(address(middleware));
        vm.stopPrank();
    }

    function _registerOperatorToNetwork(address _operator, address _vault, bool skipRegister, bool skipOptIn) public {
        vm.startPrank(_operator);
        if (!skipRegister) {
            registry.register();
        }
        if (!skipOptIn) {
            operatorNetworkOptInServiceMock.optIn(tanssi);
            operatorVaultOptInServiceMock.optIn(address(_vault));
        }
        vm.stopPrank();
    }

    function testConstructorFailsWithInvalidSlashingWindow() public {
        uint48 EPOCH_DURATION_ = 100;
        uint48 SHORT_SLASHING_WINDOW_ = 99;

        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__SlashingWindowTooShort.selector);

        new Middleware(
            address(0),
            address(0),
            address(0),
            address(0),
            owner,
            EPOCH_DURATION_,
            SHORT_SLASHING_WINDOW_ // slashing window less than epoch duration
        );

        vm.stopPrank();
    }

    function testGetEpochStartTs() public view {
        // Test first epoch
        assertEq(middleware.getEpochStartTs(0), START_TIME);

        // Test subsequent epochs
        assertEq(middleware.getEpochStartTs(1), START_TIME + NETWORK_EPOCH_DURATION);
        assertEq(middleware.getEpochStartTs(2), START_TIME + 2 * NETWORK_EPOCH_DURATION);

        // Test large epoch number
        uint48 largeEpoch = 1000;
        assertEq(middleware.getEpochStartTs(largeEpoch), START_TIME + largeEpoch * NETWORK_EPOCH_DURATION);
    }

    function testGetEpochAtTs() public view {
        // Test start time
        assertEq(middleware.getEpochAtTs(uint48(START_TIME)), 0);

        // Test middle of first epoch
        assertEq(middleware.getEpochAtTs(uint48(START_TIME + NETWORK_EPOCH_DURATION / 2)), 0);

        // Test exact epoch boundaries
        assertEq(middleware.getEpochAtTs(uint48(START_TIME + NETWORK_EPOCH_DURATION)), 1);

        assertEq(middleware.getEpochAtTs(uint48(START_TIME + 2 * NETWORK_EPOCH_DURATION)), 2);

        // Test random time in later epoch
        uint48 randomOffset = 1000;
        assertEq(middleware.getEpochAtTs(uint48(START_TIME + randomOffset)), randomOffset / NETWORK_EPOCH_DURATION);
    }

    function testGetCurrentEpoch() public {
        // Test at start
        assertEq(middleware.getCurrentEpoch(), 0);

        // Test after some time has passed
        vm.warp(START_TIME + NETWORK_EPOCH_DURATION * 2 / 3);
        assertEq(middleware.getCurrentEpoch(), 0);

        // Test at exact epoch boundary
        vm.warp(START_TIME + NETWORK_EPOCH_DURATION + 1);
        assertEq(middleware.getCurrentEpoch(), 1);

        // Test in middle of later epoch
        vm.warp(START_TIME + 5 * NETWORK_EPOCH_DURATION + NETWORK_EPOCH_DURATION / 2);
        assertEq(middleware.getCurrentEpoch(), 5);
    }

    function _registerVaultToNetwork(address _vault, bool skipRegister, uint256 slashingWindowReduction) public {
        bytes32 slotValue = vm.load(address(_vault), bytes32(uint256(1)));
        uint256 newValue = uint256(SLASHING_WINDOW - slashingWindowReduction) << (26 * 8);
        bytes32 mask = bytes32(~(uint256(type(uint48).max) << (26 * 8)));
        bytes32 newSlotValue = (slotValue & mask) | bytes32(newValue);

        vm.store(address(_vault), bytes32(uint256(1)), newSlotValue);
        vm.startPrank(_vault);
        if (!skipRegister) {
            registry.register();
        }
        vm.stopPrank();
    }

    function testInitialState() public view {
        assertEq(middleware.i_network(), address(tanssi));
        assertEq(middleware.i_operatorRegistry(), address(registry));
        assertEq(middleware.i_vaultRegistry(), address(registry));
        assertEq(middleware.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(middleware.i_slashingWindow(), SLASHING_WINDOW);
        assertEq(middleware.s_subnetworksCount(), 1);
    }

    // ************************************************************************************************
    // *                                      REGISTER OPERATOR
    // ************************************************************************************************
    function testRegisterOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);

        assertEq(validators.length, 1);
        assertEq(validators[0].key, OPERATOR_KEY);
        vm.stopPrank();
    }

    function testRegisterOperatorUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.registerOperator(operator, OPERATOR_KEY);
    }

    function testRegisterOperatorAlreadyRegistered() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        vm.expectRevert(IMiddleware.Middleware__OperatorAlreadyRegistred.selector);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vm.stopPrank();
    }

    function testRegisterOperatorNotOperator() public {
        _registerOperatorToNetwork(operator, address(vault), true, false);

        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__NotOperator.selector);
        middleware.registerOperator(owner, OPERATOR_KEY);
        vm.stopPrank();
    }

    function testRegisterOperatorNotOptedIn() public {
        _registerOperatorToNetwork(operator, address(vault), false, true);

        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__OperatorNotOptedIn.selector);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vm.stopPrank();
    }

    function testRegisterOperatorWithSameKeyAsOtherOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        address operator2 = makeAddr("operator2");
        _registerOperatorToNetwork(operator2, address(vault), false, false);

        vm.startPrank(owner);

        middleware.registerOperator(operator, OPERATOR_KEY);
        vm.expectRevert(SimpleKeyRegistry32.DuplicateKey.selector);
        middleware.registerOperator(operator2, OPERATOR_KEY);

        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      UPDATE OPERATOR KEY
    // ************************************************************************************************

    function testUpdateOperatorKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        bytes32 newKey = bytes32(uint256(2));
        middleware.updateOperatorKey(operator, newKey);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);

        assertEq(validators.length, 1);
        assertEq(validators[0].key, newKey);
        vm.stopPrank();
    }

    function testUpdateOperatorKeyUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.updateOperatorKey(operator, OPERATOR_KEY);
    }

    function testUpdateOperatorKeyNotRegistered() public {
        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__OperatorNotRegistred.selector);
        middleware.updateOperatorKey(operator, OPERATOR_KEY);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      PAUSE OPERATOR
    // ************************************************************************************************
    function testPauseOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        middleware.pauseOperator(operator);
        vm.stopPrank();
    }

    function testPauseOperatorUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.pauseOperator(operator);
    }

    // ************************************************************************************************
    // *                                      UNPAUSE OPERATOR
    // ************************************************************************************************
    function testUnpauseOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        middleware.pauseOperator(operator);
        middleware.unpauseOperator(operator);
        vm.stopPrank();
    }

    function testUnpauseOperatorUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.unpauseOperator(operator);
    }

    // ************************************************************************************************
    // *                                      UNREGISTER OPERATOR
    // ************************************************************************************************
    function testUnregisterOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);

        assertEq(validators.length, 0);
        vm.stopPrank();
    }

    function testUnregisterOperatorUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.unregisterOperator(operator);
    }

    function testUnregisterOperatorGracePeriodNotPassed() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(IMiddleware.Middleware__OperatorGracePeriodNotPassed.selector);
        middleware.unregisterOperator(operator);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      REGISTER VAULT
    // ************************************************************************************************

    function testRegisterVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        assertEq(middleware.isVaultRegistered(address(vault)), true);
        vm.stopPrank();
    }

    function testRegisterVaultUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.registerVault(address(vault));
    }

    function testRegisterVaultAlreadyRegistered() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        middleware.registerVault(address(vault));

        vm.expectRevert(IMiddleware.Middleware__VaultAlreadyRegistered.selector);
        middleware.registerVault(address(vault));
        vm.stopPrank();
    }

    function testRegisterVaultNotVault() public {
        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__NotVault.selector);
        middleware.registerVault(owner);
        vm.stopPrank();
    }

    function testRegisterVaultEpochTooShort() public {
        _registerVaultToNetwork(address(vault), false, 1);

        vm.startPrank(owner);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        vm.expectRevert(IMiddleware.Middleware__VaultEpochTooShort.selector);
        middleware.registerVault(address(vault));
        vm.stopPrank();
    }

    function testRegisterVaultWithVetoSlasher() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        assertEq(middleware.isVaultRegistered(address(vault)), true);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      PAUSE VAULT
    // ************************************************************************************************

    function testPauseVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        middleware.pauseVault(address(vault));
        vm.stopPrank();
    }

    function testPauseVaultUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.pauseVault(address(vault));
    }

    // ************************************************************************************************
    // *                                      UNPAUSE VAULT
    // ************************************************************************************************

    function testUnpauseVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        middleware.pauseVault(address(vault));
        middleware.unpauseVault(address(vault));
        vm.stopPrank();
    }

    function testUnpauseVaultUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.unpauseVault(address(vault));
    }

    // ************************************************************************************************
    // *                                      UNREGISTER VAULT
    // ************************************************************************************************

    function testUnregisterVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        middleware.pauseVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterVault(address(vault));

        assertEq(middleware.isVaultRegistered(address(vault)), false);
        vm.stopPrank();
    }

    function testUnregisterVaultUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.unregisterVault(address(vault));
    }

    function testUnregisterVaultGracePeriodNotPassed() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        middleware.pauseVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(IMiddleware.Middleware__VaultGracePeriodNotPassed.selector);
        middleware.unregisterVault(address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      SET SUBNETWORKS COUNT
    // ************************************************************************************************

    function testSetSubnetworksCnt() public {
        vm.startPrank(owner);
        middleware.setSubnetworksCount(2);
        assertEq(middleware.s_subnetworksCount(), 2);
        vm.stopPrank();
    }

    function testSetSubnetworksCntInvalidIfGreaterThanZero() public {
        vm.startPrank(owner);
        middleware.setSubnetworksCount(10);
        assertEq(middleware.s_subnetworksCount(), 10);

        vm.expectRevert(IMiddleware.Middleware__InvalidSubnetworksCnt.selector);
        middleware.setSubnetworksCount(8);
        vm.stopPrank();
    }

    function testSetSubnetworksCntInvalid() public {
        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidSubnetworksCnt.selector);
        middleware.setSubnetworksCount(0);
        vm.stopPrank();
    }

    function testSetSubnetworksCntUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.setSubnetworksCount(2);
    }

    // ************************************************************************************************
    // *                                      GET OPERATOR STAKE
    // ************************************************************************************************

    function testGetOperatorStake() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 stake = middleware.getOperatorStake(operator, currentEpoch);

        assertEq(stake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetOperatorStakeIsSameForEachEpoch() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 stake = middleware.getOperatorStake(operator, currentEpoch);

        assertEq(stake, OPERATOR_STAKE);

        vm.warp(START_TIME + NETWORK_EPOCH_DURATION + 1);
        stake = middleware.getOperatorStake(operator, currentEpoch);
        assertEq(stake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetOperatorStakeIsZeroIfNotRegisteredToVault() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 stake = middleware.getOperatorStake(operator, currentEpoch);

        assertEq(stake, 0);

        vm.warp(START_TIME + NETWORK_EPOCH_DURATION + 1);
        stake = middleware.getOperatorStake(operator, currentEpoch);
        assertEq(stake, 0);
        vm.stopPrank();
    }

    function testGetOperatorStakeCached() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1); //We need this otherwise underflow in the first IF
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStakeCached = middleware.calcAndCacheStakes(currentEpoch);

        uint256 stake = middleware.getOperatorStake(operator, currentEpoch);

        assertEq(stake, totalStakeCached);
        assertEq(stake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetOperatorStakeButOperatorNotActive() public {
        address operatorUnregistered = address(1);
        _registerOperatorToNetwork(operatorUnregistered, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operatorUnregistered, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        middleware.pauseVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 stake = middleware.getOperatorStake(operatorUnregistered, currentEpoch);
        assertEq(stake, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      GET TOTAL STAKE
    // ************************************************************************************************

    function testGetTotalStake() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.getTotalStake(currentEpoch);

        assertEq(totalStake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetTotalStakeCached() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1); //We need this otherwise underflow in the first IF
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStakeCached = middleware.calcAndCacheStakes(currentEpoch);

        uint256 totalStake = middleware.getTotalStake(currentEpoch);

        assertEq(totalStake, totalStakeCached);
        assertEq(totalStake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetTotalStakeEpochTooOld() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(SLASHING_WINDOW * 2 + 1);
        vm.expectRevert(IMiddleware.Middleware__TooOldEpoch.selector);
        middleware.getTotalStake(currentEpoch);
        vm.stopPrank();
    }

    function testGetTotalStakeEpochInvalid() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(IMiddleware.Middleware__InvalidEpoch.selector);
        middleware.getTotalStake(currentEpoch + 1);
        vm.stopPrank();
    }

    function testGetTotalStakeButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.getTotalStake(currentEpoch);
        assertEq(totalStake, 0);
        vm.stopPrank();
    }
    // ************************************************************************************************
    // *                                      GET VALIDATOR SET
    // ************************************************************************************************

    function testGetValidatorSet() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);

        assertEq(validators.length, 1);
        assertEq(validators[0].key, OPERATOR_KEY);
        assertEq(validators[0].stake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testGetValidatorSetButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        assertEq(validators.length, 0);

        vm.stopPrank();
    }

    function testGetValidatorSetButOperatorHasNullKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, bytes32(0));
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        assertEq(validators.length, 0);

        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      Slashes
    // ************************************************************************************************

    function testSlash() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStakeCached = middleware.calcAndCacheStakes(currentEpoch);

        // We want to slash half of it, and this is parts per billion. so this should be
        // 500000000
        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        uint256 slashAmount = OPERATOR_STAKE / 2;
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.getTotalStake(currentEpoch);
        assertEq(totalStake, totalStakeCached - slashAmount);
        vm.stopPrank();
    }

    function testSlashUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.slash(0, OPERATOR_KEY, 0);
    }

    function testSlashEpochTooOld() public {
        vm.startPrank(owner);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        vm.expectRevert(IMiddleware.Middleware__TooOldEpoch.selector);
        middleware.slash(currentEpoch, OPERATOR_KEY, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testSlashTooBigSlashAmount() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStakeCached = middleware.calcAndCacheStakes(currentEpoch);

        uint256 slashPercentage = 3 * PARTS_PER_BILLION / 2;

        vm.expectRevert(
            abi.encodeWithSelector(
                IMiddleware.Middleware__SlashPercentageTooBig.selector, currentEpoch, operator, slashPercentage
            )
        );
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        uint256 totalStake = middleware.getTotalStake(currentEpoch);
        assertEq(totalStake, totalStakeCached);
        vm.stopPrank();
    }

    function testSlashWithNoActiveVault() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        //Creating another vault to have stake on another vault
        VaultMock vault2 = new VaultMock(delegatorFactory, slasherFactory, vaultFactory);
        DelegatorMock delegator2 = new DelegatorMock(
            address(registry),
            vaultFactory,
            address(operatorVaultOptInServiceMock),
            address(operatorNetworkOptInServiceMock),
            delegatorFactory,
            0
        );
        _registerOperatorToNetwork(operator, address(vault2), false, false);
        _registerVaultToNetwork(address(vault2), false, 0);

        vm.startPrank(owner);
        vault2.setDelegator(address(delegator2));
        vm.store(address(delegator2), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        vault2.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault2)))));

        middleware.registerVault(address(vault2));

        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        middleware.pauseVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        // 50% of slashing
        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.getTotalStake(currentEpoch);
        assertEq(totalStake, OPERATOR_STAKE / 2); //Because it slashes the operator everywhere, but the operator has stake only in vault2, since the first vault is paused
        vm.stopPrank();
    }

    function testSlashWithVetoSlasher() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.getTotalStake(currentEpoch);
        assertEq(totalStake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testSlashWithSlasherWrongType() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasherWithBadType));
        vm.store(address(slasherWithBadType), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 slashPercentage = PARTS_PER_BILLION / 2;

        vm.expectRevert(IMiddleware.Middleware__UnknownSlasherType.selector);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        uint256 totalStakeCached = middleware.calcAndCacheStakes(currentEpoch);
        uint256 totalStake = middleware.getTotalStake(currentEpoch);

        assertEq(totalStake, totalStakeCached);

        vm.stopPrank();
    }

    function testSlashCannotBeAppliedToUnregisteredKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        bytes32 unknownOperator = bytes32(uint256(2));

        vm.expectRevert(
            abi.encodeWithSelector(IMiddleware.Middleware__OperatorNotFound.selector, unknownOperator, currentEpoch)
        );
        middleware.slash(currentEpoch, unknownOperator, slashPercentage);
    }

    // ************************************************************************************************
    // *                                      CALC AND CACHE STAKES
    // ************************************************************************************************

    function testCalcAndCacheStakes() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.calcAndCacheStakes(currentEpoch);

        assertEq(totalStake, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testCalcAndCacheStakesEpochTooOld() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerVault(address(vault));

        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(SLASHING_WINDOW * 2 + 1);
        vm.expectRevert(IMiddleware.Middleware__TooOldEpoch.selector);
        middleware.calcAndCacheStakes(currentEpoch);
        vm.stopPrank();
    }

    function testCalcAndCacheStakesEpochInvalid() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        middleware.registerVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(IMiddleware.Middleware__InvalidEpoch.selector);
        middleware.calcAndCacheStakes(currentEpoch + 1);
        vm.stopPrank();
    }

    function testCalcAndCacheStakesButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        middleware.registerVault(address(vault));
        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = middleware.calcAndCacheStakes(currentEpoch);
        assertEq(totalStake, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  SIMPLE KEY REGISTRY 32
    // ************************************************************************************************

    function testSimpleKeyRegistryHistoricalKeyLookup() public {
        uint48 timestamp1 = uint48(block.timestamp);
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        vm.warp(block.timestamp + 1 days);

        assertEq(middleware.getOperatorKeyAt(operator, timestamp1), OPERATOR_KEY);
        assertEq(middleware.getCurrentOperatorKey(operator), OPERATOR_KEY);
        vm.stopPrank();
    }

    function testSimpleKeyRegistryEmptyStates() public view {
        assertEq(middleware.getCurrentOperatorKey(operator), bytes32(0));
        assertEq(middleware.getOperatorByKey(OPERATOR_KEY), address(0));
        assertEq(middleware.getOperatorKeyAt(operator, uint48(block.timestamp) + 10 days), bytes32(0));
    }

    // ************************************************************************************************
    // *                                  DISTRIBUTE REWARDS
    // ************************************************************************************************

    function testDistributeRewards() public {
        uint48 OPERATOR_SHARE = 20;
        address gateway = makeAddr("Gateway");

        Token token = new Token("Test");
        token.transfer(address(middleware), 1000);

        ODefaultOperatorRewards operatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(token), OPERATOR_SHARE);

        vm.startPrank(owner);
        middleware.setOperatorRewardsContract(address(operatorRewards));
        middleware.setGateway(gateway);

        vm.startPrank(address(middleware));
        token.approve(address(operatorRewards), 1000);

        uint256 epoch = 0;
        uint256 eraIndex = 0;
        uint256 totalPointsToken = 100;
        uint256 tokensInflatedToken = 1000;
        bytes32 rewardsRoot = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;

        vm.startPrank(gateway);
        middleware.distributeRewards(
            epoch, eraIndex, totalPointsToken, tokensInflatedToken, rewardsRoot, address(token)
        );
    }

    function testDistributeRewardsUnauthorized() public {
        uint256 epoch = 0;
        uint256 eraIndex = 0;
        uint256 totalPointsToken = 100;
        uint256 tokensInflatedToken = 1000;
        bytes32 rewardsRoot = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;
        address tokenAddress = makeAddr("TanssiToken");

        vm.expectRevert(IMiddleware.Middleware__CallerNotGateway.selector);
        middleware.distributeRewards(epoch, eraIndex, totalPointsToken, tokensInflatedToken, rewardsRoot, tokenAddress);
    }

    // ************************************************************************************************
    // *                                  SET REWARDS CONTRACTS
    // ************************************************************************************************

    function testSetRewardsContracts() public {
        uint48 OPERATOR_SHARE = 20;
        Token token = new Token("Test");

        ODefaultOperatorRewards operatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(token), OPERATOR_SHARE);

        vm.startPrank(owner);
        vm.expectEmit(true, true, false, true);
        emit IMiddleware.OperatorRewardContractSet(address(operatorRewards));
        middleware.setOperatorRewardsContract(address(operatorRewards));

        assertEq(middleware.s_operatorRewards(), address(operatorRewards));
        vm.stopPrank();
    }

    function testSetRewardsContractsUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.setOperatorRewardsContract(address(0));
    }

    function testSetRewardsContractsInvalid() public {
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware.setOperatorRewardsContract(address(0));
    }

    // ************************************************************************************************
    // *                                  GET OPERATORS BY EPOCH
    // ************************************************************************************************

    function testGetOperatorsByEpoch() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = middleware.getOperatorsByEpoch(currentEpoch);

        assertEq(operators.length, 1);
        assertEq(operators[0], operator);
        vm.stopPrank();
    }

    function testGetMultipleOperatorsByEpoch() public {
        address operator2 = makeAddr("operator2");
        bytes32 OPERATOR2_KEY = bytes32(uint256(2));
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerOperatorToNetwork(operator2, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerOperator(operator2, OPERATOR2_KEY);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = middleware.getOperatorsByEpoch(currentEpoch);

        assertEq(operators.length, 2);
        assertEq(operators[0], operator);
        assertEq(operators[1], operator2);
        vm.stopPrank();
    }

    function testGetOperatorsByEpochButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.pauseOperator(operator);
        vm.warp(NETWORK_EPOCH_DURATION + 1);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = middleware.getOperatorsByEpoch(currentEpoch);

        assertEq(operators.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  SEND CURRENT OPERATORS KEYS
    // ************************************************************************************************

    function testSendCurrentOperatorKeys() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        address gateway = makeAddr("Gateway");

        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));
        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.setGateway(address(gateway));

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 1);
    }

    function testSendCurrentOperatorKeysButNoOperators() public {
        address gateway = makeAddr("Gateway");

        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));
        vm.startPrank(owner);
        middleware.setGateway(address(gateway));

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButOperatorUnregistered() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);

        address gateway = makeAddr("Gateway");

        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));
        vm.startPrank(owner);
        middleware.setGateway(address(gateway));

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButOperatorDisabled() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);

        address gateway = makeAddr("Gateway");

        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));
        vm.startPrank(owner);
        middleware.setGateway(address(gateway));

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButGatewayNotSet() public {
        vm.expectRevert(IMiddleware.Middleware__GatewayNotSet.selector);
        middleware.sendCurrentOperatorsKeys();
    }

    // ************************************************************************************************
    // *                                  GET OPERATOR VAULT PAIRS
    // ************************************************************************************************

    function testGetOperatorVaultPairs() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[0].vaults[0], address(vault));
        vm.stopPrank();
    }

    function testGetOperatorVaultPairsButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 0);
        vm.stopPrank();
    }

    function testGetOperatorVaultPairsButOperatorPaused() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));
        middleware.pauseOperator(operator);
        vm.warp(NETWORK_EPOCH_DURATION + 1);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, address(0));
        assertEq(operatorVaultPairs[0].vaults.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  GET OPERATOR VAULT PAIRS
    // ************************************************************************************************

    function testGetOperatorVaults() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.warp(NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        (uint256 vaultIdx, address[] memory vaults) = middleware.getOperatorVaults(operator, currentEpoch);

        assertEq(vaultIdx, 1);
        assertEq(vaults.length, 1);
        assertEq(vaults[0], address(vault));
        vm.stopPrank();
    }

    function testGetOperatorVaultsButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));
        middleware.pauseOperator(operator);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.warp(NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        (uint256 vaultIdx, address[] memory vaults) = middleware.getOperatorVaults(operator, currentEpoch);

        assertEq(vaultIdx, 1);
        assertEq(vaults.length, 1);
        assertEq(vaults[0], address(vault));
        vm.stopPrank();
    }

    function testGetOperatorVaultsButNoVaultsActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));
        middleware.pauseVault(address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        (uint256 vaultIdx, address[] memory vaults) = middleware.getOperatorVaults(operator, currentEpoch);

        assertEq(vaultIdx, 0);
        assertEq(vaults.length, 1);
        assertEq(vaults[0], address(0));
        vm.stopPrank();
    }

    function testGetOperatorVaultsButNoVaults() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.startPrank(owner);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerVault(address(vault));
        middleware.pauseVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterVault(address(vault));

        uint48 currentEpoch = middleware.getCurrentEpoch();
        (uint256 vaultIdx, address[] memory vaults) = middleware.getOperatorVaults(operator, currentEpoch);

        assertEq(vaultIdx, 0);
        assertEq(vaults.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  SET STAKER REWARD CONTRACT
    // ************************************************************************************************

    function testSetStakerRewardContract() public {
        uint48 OPERATOR_SHARE = 20;
        Token token = new Token("Test");
        address stakerRewardAddress = makeAddr("StakerRewardAddress");

        ODefaultOperatorRewards operatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(token), OPERATOR_SHARE);

        vm.startPrank(owner);
        middleware.setOperatorRewardsContract(address(operatorRewards));

        vm.expectEmit(true, true, false, true);
        emit IODefaultOperatorRewards.SetStakerRewardContract(stakerRewardAddress, address(vault));
        middleware.setStakerRewardContract(stakerRewardAddress, address(vault));
        assertEq(operatorRewards.s_vaultToStakerRewardsContract(address(vault)), stakerRewardAddress);
        vm.stopPrank();
    }

    function testSetStakerRewardContractUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        middleware.setStakerRewardContract(address(0), address(vault));
    }

    function testSetStakerRewardContractInvalid() public {
        uint48 OPERATOR_SHARE = 20;
        Token token = new Token("Test");

        ODefaultOperatorRewards operatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), address(token), OPERATOR_SHARE);

        vm.startPrank(owner);
        middleware.setOperatorRewardsContract(address(operatorRewards));

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidAddress.selector);
        middleware.setStakerRewardContract(address(0), address(vault));
    }

    function testSetStakerRewardContractButOperatorRewardsNotSet() public {
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__OperatorRewardsNotSet.selector);
        middleware.setStakerRewardContract(address(0), address(vault));
    }
}
