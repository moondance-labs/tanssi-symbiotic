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

import {Test, console2} from "forge-std/Test.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {IOzAccessControl} from "@symbiotic-middleware/interfaces/extensions/managers/access/IOzAccessControl.sol";
import {PauseableEnumerableSet} from "@symbiotic-middleware/libraries/PauseableEnumerableSet.sol";
import {OperatorManager} from "@symbiotic-middleware/managers/OperatorManager.sol";
import {KeyManager256} from "@symbiotic-middleware/extensions/managers/keys/KeyManager256.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";

import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {MiddlewareV2} from "./utils/MiddlewareV2.sol";
import {MiddlewareV3} from "./utils/MiddlewareV3.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";
import {QuickSort} from "src/contracts/libraries/QuickSort.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";

import {DelegatorMock} from "../mocks/symbiotic/DelegatorMock.sol";
import {OptInServiceMock} from "../mocks/symbiotic/OptInServiceMock.sol";
import {RegistryMock} from "../mocks/symbiotic/RegistryMock.sol";
import {VaultMock} from "../mocks/symbiotic/VaultMock.sol";
import {SharedVaultMock} from "../mocks/symbiotic/SharedVaultMock.sol";
import {Token} from "../mocks/Token.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using QuickSort for IMiddleware.ValidatorData[];

    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant OPERATOR_STAKE = 10 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant PREV_OPERATOR_KEY = bytes32(uint256(4));
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    bytes32 public constant MIDDLEWARE_STORAGE_LOCATION =
        0xca64b196a0d05040904d062f739ed1d1e1d3cc5de78f7001fb9039595fce9100;
    bytes32 public constant MIDDLEWARE_STORAGE_CACHE_LOCATION =
        0x93540b1a1dc30969947272428a8d0331ac0b23f753e3edd38c70f80cf0835100;

    uint8 public constant ORACLE_DECIMALS = 18;
    int256 public constant ORACLE_CONVERSION_TOKEN = 3000 ether;

    uint48 public constant START_TIME = 1;

    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    bytes32 public constant FORWARDER_ROLE = keccak256("FORWARDER_ROLE");

    address tanssi = makeAddr("tanssi");
    address vaultFactory = makeAddr("vaultFactory");
    address slasherFactory = makeAddr("slasherFactory");
    address delegatorFactory = makeAddr("delegatorFactory");

    address owner = makeAddr("owner");
    address operator = makeAddr("operator");
    address gateway = makeAddr("gateway");
    address forwarder = makeAddr("forwarder");
    address readHelper;

    NetworkMiddlewareService networkMiddlewareService;
    OptInServiceMock operatorNetworkOptInServiceMock;
    OptInServiceMock operatorVaultOptInServiceMock;
    DelegatorMock delegator;
    Middleware middleware;
    Middleware middlewareImpl;
    RegistryMock registry;
    VaultMock vault;
    Slasher slasher;
    VetoSlasher vetoSlasher;
    Slasher slasherWithBadType;
    Token collateral;
    MockV3Aggregator collateralOracle;

    DeployRewards deployRewards;
    DeployCollateral deployCollateral;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewardsFactory stakerRewardsFactory;

    IODefaultStakerRewards.InitParams stakerRewardsParams = IODefaultStakerRewards.InitParams({
        adminFee: 0,
        defaultAdminRoleHolder: owner,
        adminFeeClaimRoleHolder: owner,
        adminFeeSetRoleHolder: owner,
        implementation: address(0)
    });

    function setUp() public {
        vm.startPrank(owner);

        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        deployCollateral = new DeployCollateral();

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

        collateral = Token(deployCollateral.deployCollateral("Token"));

        collateralOracle = new MockV3Aggregator(ORACLE_DECIMALS, ORACLE_CONVERSION_TOKEN);

        vault = new VaultMock(delegatorFactory, slasherFactory, vaultFactory, address(collateral));
        vault.setDelegator(address(delegator));

        vm.store(address(delegator), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        readHelper = address(new OBaseMiddlewareReader());

        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        address operatorRewardsAddress =
            deployRewards.deployOperatorRewardsContract(tanssi, address(networkMiddlewareService), 5000, owner);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            vaultFactory, address(networkMiddlewareService), operatorRewardsAddress, tanssi, owner
        );
        stakerRewardsFactory = ODefaultStakerRewardsFactory(stakerRewardsFactoryAddress);
        vm.mockCall(
            address(stakerRewardsFactory),
            abi.encodeWithSelector(IODefaultStakerRewardsFactory.create.selector),
            abi.encode(makeAddr("stakerRewards"))
        );

        middlewareImpl = new Middleware();
        middleware = Middleware(address(new MiddlewareProxy(address(middlewareImpl), "")));
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(registry),
            vaultRegistry: address(registry),
            operatorNetworkOptIn: address(operatorNetworkOptInServiceMock),
            owner: owner,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper
        });
        middleware.initialize(params);
        middleware.reinitializeRewards(operatorRewardsAddress, stakerRewardsFactoryAddress);

        middleware.setGateway(address(gateway));
        middleware.setCollateralToOracle(address(collateral), address(collateralOracle));

        stakerRewardsParams.implementation =
            address(new ODefaultStakerRewards(address(networkMiddlewareService), tanssi));

        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware));

        vm.startPrank(tanssi);
        registry.register();
        networkMiddlewareService.setMiddleware(address(middleware));
        vm.stopPrank();

        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));
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

    function testInitializeFailsWithInvalidSlashingWindow() public {
        uint48 EPOCH_DURATION_ = 100;
        uint48 SHORT_SLASHING_WINDOW_ = 99;

        vm.startPrank(owner);

        readHelper = address(new OBaseMiddlewareReader());
        Middleware _middleware = new Middleware();
        Middleware middlewareProxy = Middleware(address(new MiddlewareProxy(address(_middleware), "")));
        vm.expectRevert(IMiddleware.Middleware__SlashingWindowTooShort.selector);
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(registry),
            vaultRegistry: address(registry),
            operatorNetworkOptIn: address(operatorNetworkOptInServiceMock),
            owner: owner,
            epochDuration: EPOCH_DURATION_,
            slashingWindow: SHORT_SLASHING_WINDOW_,
            reader: readHelper
        });
        Middleware(address(middlewareProxy)).initialize(params);

        vm.stopPrank();
    }

    function testGetEpochStartTs() public view {
        // Test first epoch
        assertEq(EpochCapture(address(middleware)).getEpochStart(0), START_TIME);

        // Test subsequent epochs
        assertEq(EpochCapture(address(middleware)).getEpochStart(1), START_TIME + NETWORK_EPOCH_DURATION);
        assertEq(EpochCapture(address(middleware)).getEpochStart(2), START_TIME + 2 * NETWORK_EPOCH_DURATION);

        // Test large epoch number
        uint48 largeEpoch = 1000;
        assertEq(
            EpochCapture(address(middleware)).getEpochStart(largeEpoch),
            START_TIME + largeEpoch * NETWORK_EPOCH_DURATION
        );
    }

    function testGetEpochAtTs() public view {
        // Test middle of first epoch
        assertEq(
            OBaseMiddlewareReader(address(middleware)).getEpochAtTs(uint48(START_TIME + NETWORK_EPOCH_DURATION / 2)), 0
        );

        // Test exact epoch boundaries
        assertEq(
            OBaseMiddlewareReader(address(middleware)).getEpochAtTs(uint48(START_TIME + NETWORK_EPOCH_DURATION + 1)), 1
        );

        assertEq(
            OBaseMiddlewareReader(address(middleware)).getEpochAtTs(uint48(START_TIME + 2 * NETWORK_EPOCH_DURATION + 1)),
            2
        );

        // Test random time in later epoch
        uint48 randomOffset = 1000;
        assertEq(
            OBaseMiddlewareReader(address(middleware)).getEpochAtTs(uint48(START_TIME + randomOffset)),
            randomOffset / NETWORK_EPOCH_DURATION
        );
    }

    function testGetCurrentEpoch() public {
        // Test at start
        assertEq(middleware.getCurrentEpoch(), 0);

        // Test after some time has passed
        vm.warp(START_TIME + (NETWORK_EPOCH_DURATION * 2) / 3);
        assertEq(middleware.getCurrentEpoch(), 0);

        // Test at exact epoch boundary
        vm.warp(START_TIME + NETWORK_EPOCH_DURATION + 1);
        assertEq(middleware.getCurrentEpoch(), 1);

        // Test in middle of later epoch
        vm.warp(START_TIME + 5 * NETWORK_EPOCH_DURATION + NETWORK_EPOCH_DURATION / 2);
        assertEq(middleware.getCurrentEpoch(), 5);
    }

    function testSetReader() public {
        // Test at start
        address newReader = makeAddr("newReader");
        vm.startPrank(owner);
        middleware.setReader(newReader);
        vm.stopPrank();

        bytes32 ReaderStorageLocation = 0xfd87879bc98f37af7578af722aecfbe5843e5ad354da2d1e70cb5157c4ec8800;
        address storedReader = address(uint160(uint256(vm.load(address(middleware), ReaderStorageLocation))));
        assertEq(storedReader, newReader);
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
        assertEq(OBaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
        assertEq(OBaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY(), address(registry));
        assertEq(OBaseMiddlewareReader(address(middleware)).VAULT_REGISTRY(), address(registry));
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(OBaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(
            OBaseMiddlewareReader(address(middleware)).OPERATOR_NET_OPTIN(), address(operatorNetworkOptInServiceMock)
        );
        assertEq(OBaseMiddlewareReader(address(middleware)).subnetworksLength(), 1);
        assertEq(middleware.getGateway(), address(gateway));
        assertEq(middleware.getLastTimestamp(), 1); // Start time in tests is 1
        assertEq(middleware.getForwarderAddress(), address(0));
        assertEq(middleware.getInterval(), NETWORK_EPOCH_DURATION);
    }

    // ************************************************************************************************
    // *                                      REGISTER OPERATOR
    // ************************************************************************************************
    function testRegisterOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        // Get validator set for current epoch
        address[] memory operators = OBaseMiddlewareReader(address(middleware)).activeOperators();
        assertEq(operators.length, 1);
        assertEq(operators[0], operator);
    }

    function testRegisterOperatorWithEmptyKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidKey.selector);
        middleware.registerOperator(operator, abi.encode(bytes32(0)), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorWithKeyNot32BytesLong() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidKey.selector);
        middleware.registerOperator(operator, bytes("1234"), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorWithAddressZero() public {
        vm.startPrank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware.registerOperator(address(0), abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
    }

    function testRegisterOperatorAlreadyRegistered() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        vm.expectRevert(PauseableEnumerableSet.AlreadyRegistered.selector);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorNotOperator() public {
        _registerOperatorToNetwork(operator, address(vault), true, false);

        vm.startPrank(owner);
        vm.expectRevert(OperatorManager.NotOperator.selector);
        middleware.registerOperator(owner, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorNotOptedIn() public {
        _registerOperatorToNetwork(operator, address(vault), false, true);

        vm.startPrank(owner);
        vm.expectRevert(OperatorManager.OperatorNotOptedIn.selector);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();
    }

    function testRegisterOperatorWithSameKeyAsOtherOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        address operator2 = makeAddr("operator2");
        _registerOperatorToNetwork(operator2, address(vault), false, false);

        vm.startPrank(owner);

        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.expectRevert(KeyManager256.DuplicateKey.selector);
        middleware.registerOperator(operator2, abi.encode(OPERATOR_KEY), address(0));

        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      UPDATE OPERATOR KEY
    // ************************************************************************************************

    function testUpdateOperatorKey() public {
        _registerVaultAndOperator(address(0), true);

        vm.startPrank(owner);
        bytes32 newKey = bytes32(uint256(2));
        middleware.updateOperatorKey(operator, abi.encode(newKey));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);

        assertEq(validators.length, 1);
        assertEq(validators[0].key, newKey);
        vm.stopPrank();
    }

    function testUpdateOperatorKeyUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.updateOperatorKey(operator, abi.encode(OPERATOR_KEY));
    }

    // ************************************************************************************************
    // *                                      PAUSE OPERATOR
    // ************************************************************************************************
    function testPauseOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        middleware.pauseOperator(operator);
        vm.stopPrank();
    }

    function testPauseOperatorUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.pauseOperator(operator);
    }

    // ************************************************************************************************
    // *                                      UNPAUSE OPERATOR
    // ************************************************************************************************
    function testUnpauseOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        middleware.pauseOperator(operator);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        middleware.unpauseOperator(operator);
        vm.stopPrank();
    }

    function testUnpauseOperatorUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.unpauseOperator(operator);
    }

    // ************************************************************************************************
    // *                                      UNREGISTER OPERATOR
    // ************************************************************************************************
    function testUnregisterOperator() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);

        assertEq(validators.length, 0);
        vm.stopPrank();
    }

    function testUnregisterOperatorUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.unregisterOperator(operator);
    }

    function testUnregisterOperatorGracePeriodNotPassed() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(PauseableEnumerableSet.ImmutablePeriodNotPassed.selector);
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
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        assertEq(OBaseMiddlewareReader(address(middleware)).isVaultRegistered(address(vault)), true);
        vm.stopPrank();
    }

    function testRegisterVaultUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
    }

    function testRegisterVaultAlreadyRegistered() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        vm.expectRevert(VaultManager.VaultAlreadyRegistered.selector);

        vm.mockCall(
            address(stakerRewardsFactory),
            abi.encodeWithSelector(IODefaultStakerRewardsFactory.create.selector),
            abi.encode(makeAddr("stakerRewards2"))
        );
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        vm.stopPrank();
    }

    function testRegisterVaultNotVault() public {
        vm.startPrank(owner);
        vm.expectRevert(VaultManager.NotVault.selector);
        middleware.registerSharedVault(owner, stakerRewardsParams);
        vm.stopPrank();
    }

    function testRegisterVaultEpochTooShort() public {
        _registerVaultToNetwork(address(vault), false, 1);

        vm.startPrank(owner);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        vm.expectRevert(VaultManager.VaultEpochTooShort.selector);
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        vm.stopPrank();
    }

    function testRegisterVaultWithVetoSlasher() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(vetoSlasher));
        vm.store(address(vetoSlasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        assertEq(OBaseMiddlewareReader(address(middleware)).isVaultRegistered(address(vault)), true);
        vm.stopPrank();
    }

    function testRegisterVaultWithNoHookOverwritten() public {
        // This was added just to cover the default implementation of the _beforeRegisterSharedVault hook
        SharedVaultMock vaultMock = new SharedVaultMock();
        vaultMock.callAfterRegisterHook(address(vaultMock), stakerRewardsParams);
        assertEq(vaultMock.stakeToPower(makeAddr("mock"), 1), 0);
    }

    // ************************************************************************************************
    // *                                      PAUSE VAULT
    // ************************************************************************************************

    function testPauseVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        middleware.pauseSharedVault(address(vault));
        vm.stopPrank();
    }

    function testPauseVaultUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.pauseSharedVault(address(vault));
    }

    // ************************************************************************************************
    // *                                      UNPAUSE VAULT
    // ************************************************************************************************

    function testUnpauseVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        middleware.pauseSharedVault(address(vault));
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        middleware.unpauseSharedVault(address(vault));
        vm.stopPrank();
    }

    function testUnpauseVaultUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.unpauseSharedVault(address(vault));
    }

    // ************************************************************************************************
    // *                                      UNREGISTER VAULT
    // ************************************************************************************************

    function testUnregisterVault() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        middleware.pauseSharedVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterSharedVault(address(vault));

        assertEq(OBaseMiddlewareReader(address(middleware)).isVaultRegistered(address(vault)), false);
        vm.stopPrank();
    }

    function testUnregisterVaultUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.unregisterSharedVault(address(vault));
    }

    function testUnregisterVaultGracePeriodNotPassed() public {
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        middleware.pauseSharedVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW - 1);
        vm.expectRevert(PauseableEnumerableSet.ImmutablePeriodNotPassed.selector);
        middleware.unregisterSharedVault(address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      GET OPERATOR POWER
    // ************************************************************************************************

    function testGetOperatorPowerAt() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = EpochCapture(address(middleware)).getEpochStart(currentEpoch);
        uint256 stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);

        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(stake, expectedStake);
        vm.stopPrank();
    }

    function testGetOperatorStakeIsSameForEachEpoch() public {
        _registerVaultAndOperator(address(slasher), false);
        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = EpochCapture(address(middleware)).getEpochStart(currentEpoch);
        uint256 stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);

        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(stake, expectedStake);

        vm.warp(NETWORK_EPOCH_DURATION * 2 + 2);
        stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);

        assertEq(stake, expectedStake);
        vm.stopPrank();
    }

    function testGetOperatorStakeIsZeroIfNotRegisteredToVault() public {
        _registerVaultAndOperator(address(0), false);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = EpochCapture(address(middleware)).getEpochStart(currentEpoch);
        uint256 stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);

        assertEq(stake, 0);

        vm.warp(START_TIME + NETWORK_EPOCH_DURATION + 1);
        stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);
        assertEq(stake, 0);
        vm.stopPrank();
    }

    function testGetOperatorStakeCached() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(START_TIME + SLASHING_WINDOW + 1); //We need this otherwise underflow in the first IF
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = EpochCapture(address(middleware)).getEpochStart(currentEpoch);

        uint256 stake = OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operator);

        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(stake, expectedStake);
        vm.stopPrank();
    }

    function testGetOperatorStakeButOperatorNotActive() public {
        address operatorUnregistered = address(1);
        _registerOperatorToNetwork(operatorUnregistered, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operatorUnregistered, abi.encode(OPERATOR_KEY), address(0));
        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        middleware.pauseSharedVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = EpochCapture(address(middleware)).getEpochStart(currentEpoch);
        uint256 stake =
            OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochStartTs, operatorUnregistered);
        assertEq(stake, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      GET TOTAL STAKE
    // ************************************************************************************************

    function testGetTotalStake() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);

        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(totalStake, expectedStake);
        vm.stopPrank();
    }

    function testGetTotalStakeCached() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1); //We need this otherwise underflow in the first IF
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;

        assertEq(totalStake, expectedStake);
        vm.stopPrank();
    }

    function testGetTotalStakeButOperatorNotActive() public {
        _registerVaultAndOperator(address(slasher), false);
        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        assertEq(totalStake, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      GET VALIDATOR SET
    // ************************************************************************************************

    function testGetValidatorSet() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        vm.startPrank(owner);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);

        assertEq(validators.length, 1);
        assertEq(validators[0].key, OPERATOR_KEY);
        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(validators[0].power, expectedStake);
        vm.stopPrank();
    }

    function testGetValidatorSetButOperatorNotActive() public {
        _registerVaultAndOperator(address(slasher), false);
        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 0);

        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                      Slashes
    // ************************************************************************************************

    function testSlash() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        // We want to slash half of it, and this is parts per billion. so this should be
        // 500000000
        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        uint256 slashAmount = OPERATOR_STAKE / 2;

        vm.startPrank(gateway);

        // 2 events are emitted before the actual slash event in the middleware.
        vm.expectEmit(false, false, false, false);
        emit IBaseDelegator.OnSlash(tanssi.subnetwork(0), operator, slashAmount, 0);

        vm.expectEmit(false, false, false, false);
        emit ISlasher.Slash(tanssi.subnetwork(0), operator, slashAmount, 0);

        vm.expectEmit(true, true, true, true);
        emit VaultManager.InstantSlash(address(vault), tanssi.subnetwork(0), slashAmount);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        uint256 expectedStake =
            (OPERATOR_STAKE - slashAmount) * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;

        assertEq(totalStake, expectedStake);
        vm.stopPrank();
    }

    function testSlashUnauthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), GATEWAY_ROLE
            )
        );
        middleware.slash(0, OPERATOR_KEY, 0);
    }

    function testSlashEpochTooOld() public {
        vm.startPrank(gateway);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        vm.expectRevert(IMiddleware.Middleware__TooOldEpoch.selector);
        middleware.slash(currentEpoch, OPERATOR_KEY, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testSlashInvalidEpoch() public {
        _registerVaultAndOperator(address(slasher), false);

        vm.startPrank(gateway);
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        vm.expectRevert(IMiddleware.Middleware__InvalidEpoch.selector);
        middleware.slash(currentEpoch + 1, OPERATOR_KEY, OPERATOR_STAKE);
        vm.stopPrank();
    }

    function testSlashTooBigSlashAmount() public {
        _registerVaultAndOperator(address(slasher), false);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 previousStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);

        uint256 slashPercentage = (3 * PARTS_PER_BILLION) / 2;

        vm.expectRevert(
            abi.encodeWithSelector(
                IMiddleware.Middleware__SlashPercentageTooBig.selector, currentEpoch, operator, slashPercentage
            )
        );
        vm.startPrank(gateway);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        assertEq(totalStake, previousStake);
        vm.stopPrank();
    }

    function testSlashWithNoActiveVault() public {
        _registerVaultAndOperator(address(slasher), false);

        //Creating another vault to have stake on another vault
        VaultMock vault2 = new VaultMock(delegatorFactory, slasherFactory, vaultFactory, address(collateral));
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

        middleware.registerSharedVault(address(vault2), stakerRewardsParams);

        vault.setSlasher(address(slasher));
        vm.store(address(slasher), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        middleware.pauseSharedVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        // 50% of slashing
        uint256 slashPercentage = PARTS_PER_BILLION / 2;

        vm.startPrank(gateway);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);

        uint256 expectedStake = (OPERATOR_STAKE / 2) * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(totalStake, expectedStake); //Because it slashes the operator everywhere, but the operator has stake only in vault2, since the first vault is paused
        vm.stopPrank();
    }

    function testSlashWithVetoSlasher() public {
        _registerVaultAndOperator(address(vetoSlasher), true);

        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        uint256 slashAmount = OPERATOR_STAKE / 2;

        vm.startPrank(gateway);
        vm.expectEmit(false, false, false, false);
        emit IVetoSlasher.RequestSlash(0, tanssi.subnetwork(0), operator, slashAmount, 0, 0);

        vm.expectEmit(true, true, true, true);
        emit VaultManager.VetoSlash(address(vault), tanssi.subnetwork(0), 0);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        uint256 expectedStake = OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN) / 10 ** ORACLE_DECIMALS;
        assertEq(totalStake, expectedStake);
        vm.stopPrank();
    }

    function testSlashWithSlasherWrongType() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vault.setSlasher(address(slasherWithBadType));
        vm.store(address(slasherWithBadType), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        vm.expectRevert(VaultManager.UnknownSlasherType.selector);
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 previousStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);
        uint256 slashPercentage = PARTS_PER_BILLION / 2;

        vm.startPrank(gateway);
        // TODO we should also test this for UnknownSlasherType
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);

        uint256 totalStake = OBaseMiddlewareReader(address(middleware)).getTotalStake(currentEpoch);

        assertEq(totalStake, previousStake);

        vm.stopPrank();
    }

    function testSlashCannotBeAppliedToUnregisteredKey() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.startPrank(owner);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 slashPercentage = PARTS_PER_BILLION / 2;
        bytes32 unknownOperator = bytes32(uint256(2));

        vm.startPrank(gateway);
        vm.expectRevert(
            abi.encodeWithSelector(IMiddleware.Middleware__OperatorNotFound.selector, unknownOperator, currentEpoch)
        );
        middleware.slash(currentEpoch, unknownOperator, slashPercentage);
    }

    function testSlashWithInvalidSlasherType() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 slashPercentage = PARTS_PER_BILLION / 2;

        vm.mockCall(address(slasher), IEntity.TYPE.selector, abi.encode(uint256(2)));

        vm.mockCall(
            address(vaultFactory), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );
        vm.startPrank(gateway);
        vm.expectRevert(VaultManager.UnknownSlasherType.selector);
        middleware.slash(currentEpoch, OPERATOR_KEY, slashPercentage);
    }

    // ************************************************************************************************
    // *                                      KEY MANAGER 256
    // ************************************************************************************************

    function testSimpleKeyRegistryHistoricalKeyLookup() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 timestamp1 = uint48(block.timestamp);

        assertEq(
            OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, timestamp1), abi.encode(OPERATOR_KEY)
        );
        assertEq(middleware.operatorKey(operator), abi.encode(OPERATOR_KEY));
        vm.stopPrank();
    }

    function testSimpleKeyRegistryEmptyStates() public view {
        assertEq(middleware.operatorKey(operator), abi.encode(bytes32(0)));
        assertEq(middleware.operatorByKey(abi.encode(OPERATOR_KEY)), address(0));
        assertEq(
            OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(block.timestamp) + 10 days),
            abi.encode(bytes32(0))
        );
    }

    // ************************************************************************************************
    // *                                  DISTRIBUTE REWARDS
    // ************************************************************************************************

    function testDistributeRewards() public {
        Token token = new Token("Test", 18);
        token.transfer(address(middleware), 1000);

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

        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), GATEWAY_ROLE
            )
        );
        middleware.distributeRewards(epoch, eraIndex, totalPointsToken, tokensInflatedToken, rewardsRoot, tokenAddress);
    }

    function testDistributeRewardsWithInsufficientBalance() public {
        uint256 epoch = 0;
        uint256 eraIndex = 0;
        uint256 totalPointsToken = 100;
        uint256 tokensInflatedToken = 1000;
        bytes32 rewardsRoot = 0x4b0ddd8b9b8ec6aec84bcd2003c973254c41d976f6f29a163054eec4e7947810;

        Token token = new Token("Test", 18);
        token.transfer(address(middleware), 800);

        vm.startPrank(gateway);
        vm.expectRevert(IMiddleware.Middleware__InsufficientBalance.selector);
        middleware.distributeRewards(
            epoch, eraIndex, totalPointsToken, tokensInflatedToken, rewardsRoot, address(token)
        );
    }

    // ************************************************************************************************
    // *                                  GET OPERATORS BY EPOCH
    // ************************************************************************************************

    function testGetOperatorsByEpoch() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = OBaseMiddlewareReader(address(middleware)).getOperatorsByEpoch(currentEpoch);

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
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = OBaseMiddlewareReader(address(middleware)).getOperatorsByEpoch(currentEpoch);

        assertEq(operators.length, 2);
        assertEq(operators[0], operator);
        assertEq(operators[1], operator2);
        vm.stopPrank();
    }

    function testGetOperatorsByEpochButOperatorNotActive() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.pauseOperator(operator);
        vm.warp(NETWORK_EPOCH_DURATION + 2);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory operators = OBaseMiddlewareReader(address(middleware)).getOperatorsByEpoch(currentEpoch);

        assertEq(operators.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  SEND CURRENT OPERATORS KEYS
    // ************************************************************************************************

    function testSendCurrentOperatorKeys() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(NETWORK_EPOCH_DURATION * 2 + 2);
        vm.roll(80);
        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 1);
    }

    function testSendCurrentOperatorKeysButOperatorWithZeroPower() public {
        _registerVaultAndOperator(address(slasher), false);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        vm.roll(80);
        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButNoOperators() public {
        vm.startPrank(owner);
        vm.roll(80);
        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButOperatorUnregistered() public {
        _registerVaultAndOperator(address(0), false);

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        vm.roll(80);
        middleware.unregisterOperator(operator);

        vm.startPrank(owner);

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButOperatorDisabled() public {
        _registerVaultAndOperator(address(0), false);

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        vm.roll(80);

        vm.startPrank(owner);

        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    function testSendCurrentOperatorKeysButGatewayNotSet() public {
        bytes32 slot = bytes32(uint256(MIDDLEWARE_STORAGE_LOCATION));

        vm.store(address(middleware), slot, bytes32(0));

        vm.roll(80);

        vm.expectRevert(IMiddleware.Middleware__GatewayNotSet.selector);
        middleware.sendCurrentOperatorsKeys();
    }

    function testSendCurrentOperatorKeysButIsLimitedByMinIntervalBlock() public {
        _registerVaultAndOperator(address(slasher), true);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        vm.roll(80);
        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 1);

        vm.warp(NETWORK_EPOCH_DURATION + 2 + 60); // + 60 seconds ≈ 5 blocks
        vm.roll(85);
        keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 0);
    }

    // ************************************************************************************************
    // *                                  GET OPERATOR VAULT PAIRS
    // ************************************************************************************************

    function testGetOperatorVaultPairs() public {
        _registerVaultAndOperator(address(0), false);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[0].vaults[0], address(vault));
        vm.stopPrank();
    }

    function testGetOperatorVaultPairsButOperatorNotActive() public {
        _registerVaultAndOperator(address(0), false);

        middleware.pauseOperator(operator);
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 0);
        vm.stopPrank();
    }

    function testGetOperatorVaultPairsButOperatorPaused() public {
        _registerVaultAndOperator(address(0), false);
        middleware.pauseOperator(operator);
        vm.warp(NETWORK_EPOCH_DURATION + 1);

        uint48 currentEpoch = middleware.getCurrentEpoch();
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  GET OPERATOR VAULT PAIRS
    // ************************************************************************************************

    function testGetOperatorVaults() public {
        _registerVaultAndOperator(address(0), false);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochTs = middleware.getEpochStart(currentEpoch);
        (uint256 vaultIdx, address[] memory vaults) =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaults(operator, epochTs);

        assertEq(vaultIdx, 1);
        assertEq(vaults.length, 1);
        assertEq(vaults[0], address(vault));
        vm.stopPrank();
    }

    function testGetOperatorVaultsButOperatorNotActive() public {
        _registerVaultAndOperator(address(0), false);
        middleware.pauseOperator(operator);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochTs = middleware.getEpochStart(currentEpoch);
        (uint256 vaultIdx, address[] memory vaults) =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaults(operator, epochTs);

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
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        middleware.pauseSharedVault(address(vault));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epochTs = middleware.getEpochStart(currentEpoch);
        (uint256 vaultIdx, address[] memory vaults) =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaults(operator, epochTs);

        assertEq(vaultIdx, 0);
        assertEq(vaults.length, 0);
        vm.stopPrank();
    }

    function testGetOperatorVaultsButNoVaults() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.mockCall(
            address(vault), abi.encodeWithSelector(IVault.activeBalanceOf.selector, operator), abi.encode(1 ether)
        );

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        middleware.pauseSharedVault(address(vault));
        vm.warp(START_TIME + SLASHING_WINDOW + 1);
        middleware.unregisterSharedVault(address(vault));

        uint48 currentEpoch = middleware.getCurrentEpoch();
        (uint256 vaultIdx, address[] memory vaults) =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaults(operator, currentEpoch);

        assertEq(vaultIdx, 0);
        assertEq(vaults.length, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                  SET OPERATORS REWARD SHARE
    // ************************************************************************************************

    function testSetOperatorShareOnOperatorRewards() public {
        uint48 newOperatorShare = 3000;
        vm.startPrank(owner);
        vm.expectEmit(true, true, false, false);
        emit IODefaultOperatorRewards.SetOperatorShare(newOperatorShare);
        middleware.setOperatorShareOnOperatorRewards(newOperatorShare);
    }

    // ************************************************************************************************
    // *                                        QUICK SORT
    // ************************************************************************************************

    function testQuickSort() public pure {
        IMiddleware.ValidatorData[] memory validators = new IMiddleware.ValidatorData[](5);
        validators[0] = IMiddleware.ValidatorData(0, bytes32(0));
        validators[1] = IMiddleware.ValidatorData(1, bytes32(uint256(1)));
        validators[2] = IMiddleware.ValidatorData(2, bytes32(uint256(2)));
        validators[3] = IMiddleware.ValidatorData(3, bytes32(uint256(3)));
        validators[4] = IMiddleware.ValidatorData(4, bytes32(uint256(4)));

        IMiddleware.ValidatorData[] memory sortedValidators = validators.quickSort(0, int256(validators.length - 1));

        for (uint256 i = 0; i < validators.length - 1; i++) {
            assertGe(sortedValidators[i].power, sortedValidators[i + 1].power);
        }
    }

    // ************************************************************************************************
    // *                                        UPGRADEABLE
    // ************************************************************************************************

    function testMiddlewareIsUpgradeable() public {
        uint48 OPERATOR_SHARE = 2000;

        ODefaultOperatorRewards(
            deployRewards.deployOperatorRewardsContract(
                tanssi, address(networkMiddlewareService), OPERATOR_SHARE, owner
            )
        );

        vm.prank(owner);

        assertEq(middleware.VERSION(), 1);
        assertEq(middleware.i_operatorRewards(), address(operatorRewards));

        MiddlewareV2 middlewareImplV2 = new MiddlewareV2();
        bytes memory emptyBytes = hex"";
        vm.prank(owner);
        middleware.upgradeToAndCall(address(middlewareImplV2), emptyBytes);

        assertEq(middleware.VERSION(), 2);

        address gatewayAddress = makeAddr("gatewayAddress");

        vm.prank(owner);
        vm.expectRevert(); //Function doesn't exists
        middleware.setGateway(gatewayAddress);

        middleware.upgradeToAndCall(address(middlewareImpl), emptyBytes);
        assertEq(middleware.VERSION(), 1);

        vm.prank(owner);
        middleware.setGateway(gatewayAddress);
    }

    function testMiddlewareIsUpgradeableButMiddlewareV3IsNotUpgradeable() public {
        address newGateway = makeAddr("newGateway");
        vm.prank(owner);

        middleware.setGateway(newGateway);
        assertEq(middleware.VERSION(), 1);
        assertEq(address(middleware.getGateway()), newGateway);

        MiddlewareV3 middlewareImplV3 = new MiddlewareV3(address(operatorRewards));
        bytes memory emptyBytes = hex"";
        vm.prank(owner);
        middleware.upgradeToAndCall(address(middlewareImplV3), emptyBytes);

        assertEq(middleware.VERSION(), 3);

        vm.expectRevert(); //Doesn't exists
        middleware.setGateway(address(0));

        vm.expectRevert(MiddlewareV3.MiddlewareV3__UpgradeNotAuthorized.selector); //Contract is not upgradeable anymore
        middleware.upgradeToAndCall(address(middlewareImpl), emptyBytes);
    }

    // ************************************************************************************************
    // *                                        OPERATORS LENGTH
    // ************************************************************************************************

    function testOperatorsLength() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint256 operatorsLength = OBaseMiddlewareReader(address(middleware)).operatorsLength();

        assertEq(operatorsLength, 1);
    }

    // ************************************************************************************************
    // *                                        OPERATOR WITH TIMES AT
    // ************************************************************************************************

    function testOperatorWithTimesAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        (address operator_, uint48 startTime, uint48 endTime) =
            OBaseMiddlewareReader(address(middleware)).operatorWithTimesAt(0);

        assertEq(operator_, operator);
        assertEq(startTime, 1);
        assertEq(endTime, 0);
    }

    // ************************************************************************************************
    // *                                        ACTIVE OPERATORS
    // ************************************************************************************************

    function testActiveOperators() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        address[] memory activeOperators = OBaseMiddlewareReader(address(middleware)).activeOperators();

        assertEq(activeOperators.length, 1);
        assertEq(activeOperators[0], operator);
    }

    // ************************************************************************************************
    // *                                        ACTIVE OPERATORS AT
    // ************************************************************************************************

    function testActiveOperatorsAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        address[] memory activeOperators =
            OBaseMiddlewareReader(address(middleware)).activeOperatorsAt(currentEpochStartTs);

        assertEq(activeOperators.length, 1);
        assertEq(activeOperators[0], operator);
    }

    // ************************************************************************************************
    // *                                        OPERATOR WAS ACTIVE AT
    // ************************************************************************************************

    function testOperatorWasActiveAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        bool wasActive = OBaseMiddlewareReader(address(middleware)).operatorWasActiveAt(currentEpochStartTs, operator);

        assertEq(wasActive, true);
    }

    // ************************************************************************************************
    // *                                        IS OPERATOR REGISTERED
    // ************************************************************************************************

    function testIsOperatorRegistered() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        bool isRegistered = OBaseMiddlewareReader(address(middleware)).isOperatorRegistered(operator);

        assertEq(isRegistered, true);
    }

    // ************************************************************************************************
    // *                                        SUBNETWORK WITH TIMES AT
    // ************************************************************************************************

    function testSubnetworkWithTimesAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        (uint160 subnetworkAddress, uint48 startTime, uint48 endTime) =
            OBaseMiddlewareReader(address(middleware)).subnetworkWithTimesAt(0);

        assertEq(subnetworkAddress, 0);
        assertEq(startTime, 1);
        assertEq(endTime, 0);
    }

    // ************************************************************************************************
    // *                                        ACTIVE SUBNETWORKS
    // ************************************************************************************************

    function testActiveSubnetwork() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint160[] memory activeSubnetwork = OBaseMiddlewareReader(address(middleware)).activeSubnetworks();

        assertEq(activeSubnetwork.length, 1);
        assertEq(activeSubnetwork[0], 0);
    }

    // ************************************************************************************************
    // *                                        ACTIVE SUBNETWORKS AT
    // ************************************************************************************************

    function testActiveSubnetworkAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);

        uint160[] memory activeSubnetwork =
            OBaseMiddlewareReader(address(middleware)).activeSubnetworksAt(currentEpochStartTs);

        assertEq(activeSubnetwork.length, 1);
        assertEq(activeSubnetwork[0], 0);
    }

    // ************************************************************************************************
    // *                                        SUBNETWORK WAS ACTIVE AT
    // ************************************************************************************************

    function testSubnetworkWasActiveAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        bool isActive = OBaseMiddlewareReader(address(middleware)).subnetworkWasActiveAt(currentEpochStartTs, 0);

        assertEq(isActive, true);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        SHARED VAULTS LENGTH
    // ************************************************************************************************

    function testSharedVaultsLength() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint256 sharedVaultsLength = OBaseMiddlewareReader(address(middleware)).sharedVaultsLength();

        assertEq(sharedVaultsLength, 1);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        SHARED VAULT WITH TIMES AT
    // ************************************************************************************************

    function testSharedVaultWithTimesAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        (address vault_, uint48 startTime, uint48 endTime) =
            OBaseMiddlewareReader(address(middleware)).sharedVaultWithTimesAt(0);

        assertEq(vault_, address(vault));
        assertEq(startTime, 1);
        assertEq(endTime, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE SHARED VAULTS
    // ************************************************************************************************

    function testActiveSharedVaults() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        address[] memory activeSharedVaults = OBaseMiddlewareReader(address(middleware)).activeSharedVaults();

        assertEq(activeSharedVaults.length, 1);
        assertEq(activeSharedVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE SHARED VAULTS AT
    // ************************************************************************************************

    function testActiveSharedVaultsAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        address[] memory activeSharedVaults =
            OBaseMiddlewareReader(address(middleware)).activeSharedVaultsAt(currentEpochStartTs);

        assertEq(activeSharedVaults.length, 1);
        assertEq(activeSharedVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        OPERATOR VAULTS LENGTH
    // ************************************************************************************************

    function testOperatorVaultsLength() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);
        _mockOperatorSpecificDelegator();
        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint256 operatorVaultsLength = OBaseMiddlewareReader(address(middleware)).operatorVaultsLength(operator);

        assertEq(operatorVaultsLength, 1);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        OPERATOR VAULT WITH TIMES AT
    // ************************************************************************************************

    function testOperatorVaultWithTimesAt() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        _mockOperatorSpecificDelegator();
        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + 2);

        (address vault_, uint48 startTime, uint48 endTime) =
            OBaseMiddlewareReader(address(middleware)).operatorVaultWithTimesAt(operator, 0);

        assertEq(vault_, address(vault));
        assertEq(startTime, 1);
        assertEq(endTime, 0);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE OPERATOR VAULTS
    // ************************************************************************************************

    function _mockOperatorSpecificDelegator() internal {
        vm.mockCall(
            address(delegator),
            abi.encodeWithSelector(IEntity.TYPE.selector),
            abi.encode(VaultManager.DelegatorType.OPERATOR_SPECIFIC)
        );

        vm.mockCall(
            address(delegator),
            abi.encodeWithSelector(IOperatorSpecificDelegator.operator.selector),
            abi.encode(operator)
        );
    }

    function testActiveOperatorVaults() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        _mockOperatorSpecificDelegator();

        vm.startPrank(owner);

        // This is done because vault is operator specific!
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + 2);

        address[] memory activeOperatorVaults =
            OBaseMiddlewareReader(address(middleware)).activeOperatorVaults(operator);

        assertEq(activeOperatorVaults.length, 1);
        assertEq(activeOperatorVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE OPERATOR VAULTS AT
    // ************************************************************************************************

    function testActiveOperatorVaultsAt() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        _mockOperatorSpecificDelegator();
        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        address[] memory activeOperatorVaults =
            OBaseMiddlewareReader(address(middleware)).activeOperatorVaultsAt(currentEpochStartTs, operator);

        assertEq(activeOperatorVaults.length, 1);
        assertEq(activeOperatorVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE VAULTS
    // ************************************************************************************************

    function testActiveVaults() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        address[] memory activeVaults = OBaseMiddlewareReader(address(middleware)).activeVaults();

        assertEq(activeVaults.length, 1);
        assertEq(activeVaults[0], address(vault));
        vm.stopPrank();
    }

    function testActiveVaultsForOperator() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        address[] memory activeVaults = OBaseMiddlewareReader(address(middleware)).activeVaults(operator);

        assertEq(activeVaults.length, 1);
        assertEq(activeVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        ACTIVE VAULTS AT
    // ************************************************************************************************

    function testActiveVaultsAtForOperator() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        address[] memory activeVaults =
            OBaseMiddlewareReader(address(middleware)).activeVaultsAt(currentEpochStartTs, operator);

        assertEq(activeVaults.length, 1);
        assertEq(activeVaults[0], address(vault));
        vm.stopPrank();
    }

    function testActiveVaultsAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        address[] memory activeVaults = OBaseMiddlewareReader(address(middleware)).activeVaultsAt(currentEpochStartTs);

        assertEq(activeVaults.length, 1);
        assertEq(activeVaults[0], address(vault));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        VAULT WAS ACTIVE AT
    // ************************************************************************************************

    function testVaultWasActiveAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        bool wasActive =
            OBaseMiddlewareReader(address(middleware)).vaultWasActiveAt(currentEpochStartTs, operator, address(vault));

        assertEq(wasActive, true);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        SHARED VAULT WAS ACTIVE AT
    // ************************************************************************************************

    function testSharedVaultWasActiveAt() public {
        _registerVaultAndOperator(address(0), false);
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        bool wasActive =
            OBaseMiddlewareReader(address(middleware)).sharedVaultWasActiveAt(currentEpochStartTs, address(vault));

        assertEq(wasActive, true);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        OPERATOR VAULT WAS ACTIVE AT
    // ************************************************************************************************

    function testOperatorVaultWasActiveAt() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);
        _mockOperatorSpecificDelegator();

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(vault));
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 currentEpochStartTs = middleware.getEpochStart(currentEpoch);
        bool wasActive = OBaseMiddlewareReader(address(middleware)).operatorVaultWasActiveAt(
            currentEpochStartTs, operator, address(vault)
        );

        assertEq(wasActive, true);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        GET OPERATOR POWER
    // ************************************************************************************************

    function testGetOperatorPower() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        _setVaultCollateral(address(vault));

        uint256 power = OBaseMiddlewareReader(address(middleware)).getOperatorPower(operator, address(vault), 0);

        assertEq(power, 0);
    }

    function testGetTotalOperatorPower() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();

        uint256 power = OBaseMiddlewareReader(address(middleware)).getOperatorPower(operator);

        assertEq(power, 0);
    }

    function testGetOperatorPowerForSpecificVaultsAndSubnetworks() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        _setVaultCollateral(address(vault));
        address[] memory vaults = new address[](1);
        vaults[0] = address(vault);
        uint160[] memory subnetworks = new uint160[](1);
        subnetworks[0] = uint160(tanssi);
        uint256 power = OBaseMiddlewareReader(address(middleware)).getOperatorPower(operator, vaults, subnetworks);

        assertEq(power, 0);
    }

    // ************************************************************************************************
    // *                                        GET OPERATOR POWER AT
    // ************************************************************************************************

    function testGetOperatorPowerAtForVault() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();
        _setVaultCollateral(address(vault));
        uint48 epoch = middleware.getCurrentEpoch();
        uint48 epochTs = middleware.getEpochStart(epoch);
        uint256 power =
            OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochTs, operator, address(vault), 0);

        assertEq(power, 0);
    }

    function testGetOperatorPowerAtForSpecificVaultsAndSubnetworks() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();

        uint48 epoch = middleware.getCurrentEpoch();
        uint48 epochTs = middleware.getEpochStart(epoch);
        _setVaultCollateral(address(vault));
        address[] memory vaults = new address[](1);
        vaults[0] = address(vault);
        uint160[] memory subnetworks = new uint160[](1);
        subnetworks[0] = uint160(tanssi);
        uint256 power =
            OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(epochTs, operator, vaults, subnetworks);

        assertEq(power, 0);
    }

    // ************************************************************************************************
    // *                                        TOTAL POWER
    // ************************************************************************************************

    function testTotalPower() public {
        _registerVaultAndOperator(address(0), false);
        vm.stopPrank();

        address[] memory operators = new address[](1);
        operators[0] = operator;
        uint256 power = OBaseMiddlewareReader(address(middleware)).totalPower(operators);

        assertEq(power, 0);
    }

    // ************************************************************************************************
    // *                                        STAKE TO POWER
    // ************************************************************************************************

    function _setVaultCollateral(
        address _vault
    )
        internal
        returns (address _collateral, address _oracle, int256 multiplier, uint8 oracleDecimals, uint8 tokenDecimals)
    {
        _collateral = makeAddr("collateral");
        _oracle = makeAddr("oracle");
        multiplier = 5000;
        oracleDecimals = 2;
        tokenDecimals = 18;

        vm.startPrank(owner);
        middleware.setCollateralToOracle(_collateral, _oracle);
        vm.stopPrank();
        _setVaultToCollateral(_vault, _collateral);

        vm.mockCall(
            _oracle,
            abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),
            abi.encode(uint80(0), multiplier, uint256(0), uint256(0), uint80(0))
        );
        vm.mockCall(
            _oracle, abi.encodeWithSelector(AggregatorV3Interface.decimals.selector), abi.encode(uint8(oracleDecimals))
        );
        vm.mockCall(
            _collateral, abi.encodeWithSelector(IERC20Metadata.decimals.selector), abi.encode(uint8(tokenDecimals))
        );
    }

    function testStakeToPowerOBaseMiddlewareReader() public {
        uint256 stake = 1000 ether;
        address _vault = makeAddr("vault");
        (,, int256 multiplier, uint8 oracleDecimals,) = _setVaultCollateral(_vault);

        // Need to do this otherwise it calls directly middleware stakeToPower and can't reach OBaseMiddlewareReader
        bytes memory baseCallData = abi.encodeWithSelector(OBaseMiddlewareReader.stakeToPower.selector, _vault, stake);

        bytes memory augmentedCallData = abi.encodePacked(baseCallData, address(middleware));

        (, bytes memory returnData) = readHelper.staticcall(augmentedCallData);

        uint256 power = abi.decode(returnData, (uint256));

        uint256 expectedPower = (stake * uint256(multiplier)) / (10 ** uint256(oracleDecimals));
        assertEq(power, expectedPower);
    }

    function testStakeToPower() public {
        uint256 stake = 1000 ether;
        address _vault = makeAddr("vault");
        (,, int256 multiplier, uint8 oracleDecimals,) = _setVaultCollateral(_vault);

        uint256 power = middleware.stakeToPower(_vault, stake);
        uint256 expectedPower = (stake * uint256(multiplier)) / (10 ** uint256(oracleDecimals));
        assertEq(power, expectedPower);
    }

    function testStakeToPowerWithNoOracle() public {
        uint256 stake = 1000;
        address _vault = makeAddr("vault");
        address _collateral = makeAddr("collateral");

        _setVaultToCollateral(_vault, _collateral);
        // Collateral is not set to an oracle

        vm.expectRevert(
            abi.encodeWithSelector(
                IOBaseMiddlewareReader.OBaseMiddlewareReader__NotSupportedCollateral.selector, _collateral
            )
        );
        middleware.stakeToPower(_vault, stake);
    }

    // ************************************************************************************************
    // *                                        INITIALIZE
    // ************************************************************************************************

    function _prepareInitializeTest() private returns (Middleware middleware2, IMiddleware.InitParams memory params) {
        middleware2 = Middleware(address(new MiddlewareProxy(address(middlewareImpl), "")));
        readHelper = address(new OBaseMiddlewareReader());
        params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(registry),
            vaultRegistry: address(registry),
            operatorNetworkOptIn: address(operatorNetworkOptInServiceMock),
            owner: owner,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper
        });
    }

    function testInitializeWithNoOwner() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.owner = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithNoReader() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.reader = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithNoNetwork() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.network = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithNoOperatorRegistry() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.operatorRegistry = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithNoVaultRegistry() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.vaultRegistry = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithNoOperatorNetworkOptIn() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.operatorNetworkOptIn = address(0);

        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithInvalidEpochDuration() public {
        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.epochDuration = 0;

        vm.expectRevert(IMiddleware.Middleware__InvalidEpochDuration.selector);
        middleware2.initialize(params);
    }

    function testInitializeWithInvalidSlashingWindow() public {
        uint48 EPOCH_DURATION_ = 100;
        uint48 SHORT_SLASHING_WINDOW_ = 99;

        (Middleware middleware2, IMiddleware.InitParams memory params) = _prepareInitializeTest();
        params.epochDuration = EPOCH_DURATION_;
        params.slashingWindow = SHORT_SLASHING_WINDOW_;

        vm.expectRevert(IMiddleware.Middleware__SlashingWindowTooShort.selector);
        middleware2.initialize(params);
    }

    // ************************************************************************************************
    // *                                  GET OPERATOR KEY AT
    // ************************************************************************************************

    function testGetOperatorKeyAtWithActiveCurrentKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        bytes memory key =
            OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(block.timestamp));

        assertEq(abi.decode(key, (bytes32)), OPERATOR_KEY);
    }

    function testGetOperatorKeyAtWithInactiveCurrentKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        middleware.pauseOperator(operator);
        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        bytes memory key =
            OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(block.timestamp));

        assertEq(abi.decode(key, (bytes32)), OPERATOR_KEY);
    }

    function testGetOperatorKeyAtWithActivePreviousKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(PREV_OPERATOR_KEY), address(0));

        uint48 activeKeyTimestamp = uint48(block.timestamp + 10);
        vm.warp(activeKeyTimestamp);

        middleware.updateOperatorKey(operator, abi.encode(OPERATOR_KEY));
        vm.stopPrank();

        bytes memory key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, activeKeyTimestamp);

        assertEq(abi.decode(key, (bytes32)), PREV_OPERATOR_KEY);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 2);

        key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(block.timestamp));
        assertEq(abi.decode(key, (bytes32)), OPERATOR_KEY);
    }

    function testGetOperatorKeyAtWithNoKey() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        // Don't register any key for the operator

        bytes memory key =
            OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(block.timestamp));

        assertEq(abi.decode(key, (bytes32)), bytes32(0));
    }

    function testGetOperatorKeyAtWithFutureTimestamp() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        // This implies that for the future the key will not be disabled.
        uint48 futureTimestamp = uint48(block.timestamp + 1000);
        bytes memory key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, futureTimestamp);

        assertEq(abi.decode(key, (bytes32)), OPERATOR_KEY);
    }

    function testGetOperatorKeyAtWithPastTimestamp() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.warp(START_TIME + 500);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        uint48 pastTimestamp = uint48(START_TIME + 100);
        bytes memory key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, pastTimestamp);

        assertEq(abi.decode(key, (bytes32)), bytes32(0));
    }

    function testGetOperatorKeyAtAfterUnregistration() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));

        vm.warp(NETWORK_EPOCH_DURATION + 2);

        uint48 activeTimestamp = uint48(block.timestamp);

        vm.warp(vm.getBlockTimestamp() + activeTimestamp + 10);
        middleware.pauseOperator(operator);

        // Warp forward and unregister, going after slashing window due to ImmutablePeriod
        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator);
        vm.stopPrank();

        bytes memory key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, activeTimestamp);
        assertEq(abi.decode(key, (bytes32)), OPERATOR_KEY);

        // Another epoch is passed and the operator is completely unregistered and the key is deactivated
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 2);

        //Had to use vm timestamp otherwise the activeTimestamp var put the previous timestamp in the stack and with via-ir this gets cached
        key = OBaseMiddlewareReader(address(middleware)).getOperatorKeyAt(operator, uint48(vm.getBlockTimestamp()));

        assertEq(abi.decode(key, (bytes32)), bytes32(0));
    }

    // ************************************************************************************************
    // *                                        SET GATEWAY
    // ************************************************************************************************

    function testSetGateway() public {
        address gateway2 = makeAddr("gateway2");
        vm.prank(owner);
        middleware.setGateway(gateway2);
        assertEq(middleware.getGateway(), gateway2);
    }

    function testSetGatewayUnauthorizedAccount() public {
        address gateway2 = makeAddr("gateway2");
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.setGateway(gateway2);
    }

    function testSetGatewayRevertIfZero() public {
        address gatewayNull = address(0);
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware.setGateway(gatewayNull);
    }

    function testSetGatewayRevertIfAlreadySet() public {
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__AlreadySet.selector);
        middleware.setGateway(gateway);
    }

    // ************************************************************************************************
    // *                                        SET FORWARDER
    // ************************************************************************************************

    function testSetForwarder() public {
        address forwarder2 = makeAddr("forwarder2");
        vm.prank(owner);
        middleware.setForwarder(forwarder2);
        assertEq(middleware.getForwarderAddress(), forwarder2);
    }

    function testSetForwarderUnauthorizedAccount() public {
        address forwarder2 = makeAddr("forwarder2");
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.setForwarder(forwarder2);
    }

    function testSetForwarderRevertIfZero() public {
        address forwarderNull = address(0);
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidAddress.selector);
        middleware.setForwarder(forwarderNull);
    }

    function testSetForwarderRevertIfAlreadySet() public {
        vm.startPrank(owner);
        middleware.setForwarder(forwarder);

        vm.expectRevert(IMiddleware.Middleware__AlreadySet.selector);
        middleware.setForwarder(forwarder);
    }

    // ************************************************************************************************
    // *                                        SET INTERVAL
    // ************************************************************************************************

    function testSetInterval() public {
        uint256 interval = 3 days;
        vm.prank(owner);
        middleware.setInterval(interval);
        assertEq(middleware.getInterval(), interval);
    }

    function testSetIntervalUnauthorizedAccount() public {
        uint256 interval = 3 days;
        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), bytes32(0)
            )
        );
        middleware.setInterval(interval);
    }

    function testSetIntervalRevertIfZero() public {
        uint256 interval = 0;
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__InvalidInterval.selector);
        middleware.setInterval(interval);
    }

    function testSetIntervalRevertIfAlreadySet() public {
        vm.prank(owner);
        vm.expectRevert(IMiddleware.Middleware__AlreadySet.selector);
        middleware.setInterval(NETWORK_EPOCH_DURATION);
    }

    // ************************************************************************************************
    // *                                        UPKEEP
    // ************************************************************************************************

    function testUpkeepWhenKeysAre0() public {
        address forwarder2 = makeAddr("forwarder2");
        vm.prank(owner);
        middleware.setForwarder(forwarder2);

        // It's not needed, it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");
        vm.prank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        assertEq(performData.length, 0);

        vm.prank(forwarder2);
        vm.expectRevert(IMiddleware.Middleware__NoPerformData.selector);
        middleware.performUpkeep(performData);
    }

    function testUpkeepWithMoreOperators() public {
        address operator2 = makeAddr("operator2");
        bytes32 OPERATOR2_KEY = bytes32(uint256(2));

        vm.startPrank(owner);
        middleware.setForwarder(forwarder);

        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerOperatorToNetwork(operator2, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        vm.startPrank(operator);
        vault.deposit(operator, OPERATOR_STAKE);
        vm.startPrank(operator2);
        vault.deposit(operator2, OPERATOR_STAKE);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        (uint8 command, IMiddleware.ValidatorData[] memory validatorsData) =
            abi.decode(performData, (uint8, IMiddleware.ValidatorData[]));
        assertEq(command, middleware.CACHE_DATA_COMMAND());
        assertEq(validatorsData.length, 2);
        vm.startPrank(forwarder);
        middleware.performUpkeep(performData);
        vm.stopPrank();
    }

    function testUpkeepShouldRevertIfNotCalledByForwarder() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        vm.expectRevert(
            abi.encodeWithSelector(
                IOzAccessControl.AccessControlUnauthorizedAccount.selector, address(this), FORWARDER_ROLE
            )
        );
        middleware.performUpkeep(performData);
    }

    function testUpkeepShouldRevertIfGatewayNotSet() public {
        // We set the gateway to 0 address
        _registerOperatorToNetwork(operator, address(vault), false, false);

        bytes32 slot = bytes32(uint256(MIDDLEWARE_STORAGE_LOCATION));

        vm.store(address(middleware), slot, bytes32(0));

        vm.startPrank(owner);
        middleware.setForwarder(forwarder);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        vm.prank(forwarder);
        vm.expectRevert(IMiddleware.Middleware__GatewayNotSet.selector);
        middleware.performUpkeep(performData);
    }

    function testUpkeepShouldRevertIfAlreadyCached() public {
        _registerOperatorToNetwork(operator, address(vault), false, false);

        bytes32 slot = bytes32(uint256(MIDDLEWARE_STORAGE_CACHE_LOCATION) + uint256(1));
        bytes32 operatorKeyToPowerEpochSlot = keccak256(abi.encode(1, slot));
        bytes32 structSlot = keccak256(abi.encode(OPERATOR_KEY, operatorKeyToPowerEpochSlot));

        vm.store(address(middleware), structSlot, bytes32(uint256(150 ether)));

        vm.startPrank(owner);
        middleware.setForwarder(forwarder);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        vm.prank(forwarder);
        vm.expectRevert(IMiddleware.Middleware__AlreadyCached.selector);
        middleware.performUpkeep(performData);
    }

    // ************************************************************************************************
    // *                                   VAULT TO COLLATERAL AND TO ORACLE
    // ************************************************************************************************

    function testVaultToCollateral() public {
        vm.mockCall(
            address(registry), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );
        vm.startPrank(owner);
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        vm.stopPrank();

        address currentCollateral = middleware.vaultToCollateral(address(vault));
        assertEq(currentCollateral, address(collateral));
    }

    function testVaultToCollateralWithNoCollateral() public {
        vm.startPrank(owner);
        vault = new VaultMock(delegatorFactory, slasherFactory, vaultFactory, address(0));
        vm.mockCall(
            address(registry), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );

        vm.expectRevert(abi.encodeWithSelector(IMiddleware.Middleware__InvalidAddress.selector));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        vm.stopPrank();
    }

    function testVaultToOracle() public {
        vm.mockCall(
            address(registry), abi.encodeWithSelector(IRegistry.isEntity.selector, address(vault)), abi.encode(true)
        );
        vm.startPrank(owner);
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        vm.stopPrank();

        address currentOracle = middleware.vaultToOracle(address(vault));
        assertEq(currentOracle, address(collateralOracle));
    }

    // ************************************************************************************************
    // *                                   SET COLLATERAL TO ORACLE
    // ************************************************************************************************

    function testSetCollateralToOracle() public {
        address _collateral = makeAddr("collateral");
        address _oracle = makeAddr("oracle");

        vm.startPrank(owner);
        middleware.setCollateralToOracle(_collateral, _oracle);
        vm.stopPrank();
        assertEq(middleware.collateralToOracle(_collateral), _oracle);
    }

    function testSetCollateralToOracleNoCollateral() public {
        address _collateral = address(0);
        address _oracle = makeAddr("oracle");

        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSelector(IMiddleware.Middleware__InvalidAddress.selector));
        middleware.setCollateralToOracle(_collateral, _oracle);
        vm.stopPrank();
    }

    function testSetCollateralToOracleRemoveOracle() public {
        address _collateral = makeAddr("collateral");
        address _oracle = makeAddr("oracle");

        vm.startPrank(owner);
        middleware.setCollateralToOracle(_collateral, _oracle);
        middleware.setCollateralToOracle(_collateral, address(0));
        vm.stopPrank();
        assertEq(middleware.collateralToOracle(_collateral), address(0));
    }

    // ************************************************************************************************
    // *                                          INTERNAL
    // ************************************************************************************************

    function _setVaultToCollateral(address vault_, address collateral_) internal {
        bytes32 slot = bytes32(uint256(MIDDLEWARE_STORAGE_LOCATION) + uint256(5)); // 5 is mapping slot number for the vault to collateral
        // Get slot for mapping with vault_
        slot = keccak256(abi.encode(vault_, slot));

        // Store array length
        vm.store(address(middleware), slot, bytes32(uint256(uint160(collateral_))));
    }

    function _registerVaultAndOperator(address slasher_, bool deposit) internal {
        _registerOperatorToNetwork(operator, address(vault), false, false);
        _registerVaultToNetwork(address(vault), false, 0);

        vm.startPrank(owner);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerSharedVault(address(vault), stakerRewardsParams);

        if (slasher_ != address(0)) {
            vault.setSlasher(slasher_);
            vm.store(address(slasher_), bytes32(uint256(0)), bytes32(uint256(uint160(address(vault)))));
        }

        if (deposit) {
            vm.startPrank(operator);
            vault.deposit(operator, OPERATOR_STAKE);
        }
    }
}
