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
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {MetadataService} from "@symbiotic/contracts/service/MetadataService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {VaultTokenized} from "@symbiotic/contracts/vault/VaultTokenized.sol";
import {NetworkRestakeDelegator} from "@symbiotic/contracts/delegator/NetworkRestakeDelegator.sol";
import {FullRestakeDelegator} from "@symbiotic/contracts/delegator/FullRestakeDelegator.sol";
import {OperatorSpecificDelegator} from "@symbiotic/contracts/delegator/OperatorSpecificDelegator.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {IOzAccessControl} from "@symbiotic-middleware/interfaces/extensions/managers/access/IOzAccessControl.sol";
import {PauseableEnumerableSet} from "@symbiotic-middleware/libraries/PauseableEnumerableSet.sol";
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {OperatorManager} from "@symbiotic-middleware/managers/OperatorManager.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {CreateAgentParams, CreateChannelParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {OperatingMode, ParaID} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Types.sol";
import {MockGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockGateway.sol";
import {GatewayProxy} from "@tanssi-bridge-relayer/snowbridge/contracts/src/GatewayProxy.sol";
import {AgentExecutor} from "@tanssi-bridge-relayer/snowbridge/contracts/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {Gateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Gateway.sol";
import {MockOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockOGateway.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {Token} from "test/mocks/Token.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 8 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant VETO_DURATION = 1 days;
    uint256 public constant SLASH_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_STAKE_ST_ETH = 90 ether;
    uint256 public constant OPERATOR_STAKE_R_ETH = 90 ether;
    uint256 public constant OPERATOR_STAKE_BTC = 9 ether;
    uint256 public constant DEFAULT_WITHDRAW_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant OPERATOR2_KEY = bytes32(uint256(2));
    bytes32 public constant OPERATOR3_KEY = bytes32(uint256(3));
    bytes32 public constant OPERATOR4_KEY = bytes32(uint256(4));
    bytes32 public constant OPERATOR5_KEY = bytes32(uint256(5));

    uint256 public constant OPERATOR_SHARE = 1;
    uint256 public constant TOTAL_NETWORK_SHARES = 2;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 10; // 10%

    uint8 public constant ORACLE_DECIMALS = 18;
    int256 public constant ORACLE_CONVERSION_ST_ETH = 3000 ether;
    int256 public constant ORACLE_CONVERSION_R_ETH = 3000 ether;
    int256 public constant ORACLE_CONVERSION_W_BTC = 90_000 ether;

    uint8 public constant USDC_ORACLE_DECIMALS = 8; // USDC_ORACLE_DECIMALS
    uint8 public constant USDC_TOKEN_DECIMALS = 6; // USDC_TOKEN_DECIMALS
    uint8 public constant USDT_ORACLE_DECIMALS = 18; // USDT_ORACLE_DECIMALS
    uint8 public constant USDT_TOKEN_DECIMALS = 18; // USDT_TOKEN_DECIMALS

    // It's Both are staking 150 USD worth in total
    uint256 public constant OPERATOR_4_STAKE_USDC = 90 * 10 ** USDC_TOKEN_DECIMALS;
    uint256 public constant OPERATOR_4_STAKE_USDT = 60 * 10 ** USDT_TOKEN_DECIMALS;
    uint256 public constant OPERATOR_5_STAKE_USDC = 60 * 10 ** USDC_TOKEN_DECIMALS;
    uint256 public constant OPERATOR_5_STAKE_USDT = 90 * 10 ** USDT_TOKEN_DECIMALS;

    uint256 public totalFullRestakePower; // Each operator participates with 100% of all operators stake
    uint256 public totalPowerVault; // By shares. Each operator participates gets 1/3 of the total power
    uint256 public totalPowerVaultSlashable; // By shares. Each operator participates gets 1/3 of the total power

    struct VaultAddresses {
        address vault;
        address delegator;
        address slasher;
        address vaultSlashable;
        address delegatorSlashable;
        address slasherSlashable;
        address vaultVetoed;
        address delegatorVetoed;
        address slasherVetoed;
    }

    struct GatewayParams {
        OperatingMode operatingMode;
        ParaID assetHubParaID;
        bytes32 assetHubAgentID;
        uint128 outboundFee;
        uint128 registerTokenFee;
        uint128 sendTokenFee;
        uint128 createTokenFee;
        uint128 maxDestinationFee;
        uint8 foreignTokenDecimals;
        UD60x18 exchangeRate;
        UD60x18 multiplier;
    }

    Middleware public middleware;
    DelegatorFactory public delegatorFactory;
    SlasherFactory public slasherFactory;
    VaultFactory public vaultFactory;
    OperatorRegistry public operatorRegistry;
    NetworkRegistry public networkRegistry;
    OptInService public operatorVaultOptInService;
    OptInService public operatorNetworkOptInService;

    MetadataService public operatorMetadataService;
    MetadataService public networkMetadataService;
    NetworkMiddlewareService public networkMiddlewareService;
    Token public stETH;
    Token public rETH;
    Token public wBTC;
    VaultConfigurator public vaultConfigurator;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);

    address public operator = makeAddr("operator");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public operator4 = makeAddr("operator4");
    address public operator5 = makeAddr("operator5");

    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");
    address public forwarder = makeAddr("forwarder");

    address tanssi;
    address otherNetwork;
    address gateway;

    VaultAddresses public vaultAddresses;
    Vault vault;
    Vault vaultSlashable;
    Vault vaultVetoed;
    Vault[] public vaults;

    VetoSlasher vetoSlasher;

    // Scripts
    DeployVault deployVault;
    DeployRewards deployRewards;
    DeployCollateral deployCollateral;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewardsFactory stakerRewardsFactory;

    function setUp() public {
        deployCollateral = new DeployCollateral();

        vm.startPrank(owner);
        address stETHAddress = deployCollateral.deployCollateral("stETH");
        stETH = Token(stETHAddress);
        stETH.mint(owner, 1_000_000 ether);
        address rETHAddress = deployCollateral.deployCollateral("rETH");
        rETH = Token(rETHAddress);
        rETH.mint(owner, 1_000_000 ether);
        address wBTCAddress = deployCollateral.deployCollateral("wBTC");
        wBTC = Token(wBTCAddress);
        wBTC.mint(owner, 1_000_000 ether);
        vm.stopPrank();

        address stEthOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_ST_ETH);
        address rEthOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_R_ETH);
        address wBtcOracle = _deployOracle(ORACLE_DECIMALS, ORACLE_CONVERSION_W_BTC);

        deployVault = new DeployVault();
        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        DeploySymbiotic deploySymbiotic = new DeploySymbiotic();

        owner = tanssi = deploySymbiotic.owner();

        DeploySymbiotic.SymbioticAddresses memory symbioticAddresses = deploySymbiotic.deploy(owner);
        vaultFactory = VaultFactory(symbioticAddresses.vaultFactory);
        delegatorFactory = DelegatorFactory(symbioticAddresses.delegatorFactory);
        slasherFactory = SlasherFactory(symbioticAddresses.slasherFactory);
        networkRegistry = NetworkRegistry(symbioticAddresses.networkRegistry);
        operatorRegistry = OperatorRegistry(symbioticAddresses.operatorRegistry);
        operatorVaultOptInService = OptInService(symbioticAddresses.operatorVaultOptInService);
        operatorNetworkOptInService = OptInService(symbioticAddresses.operatorNetworkOptInService);
        operatorMetadataService = MetadataService(symbioticAddresses.operatorMetadataService);
        networkMetadataService = MetadataService(symbioticAddresses.networkMetadataService);
        networkMiddlewareService = NetworkMiddlewareService(symbioticAddresses.networkMiddlewareService);
        vaultConfigurator = VaultConfigurator(symbioticAddresses.vaultConfigurator);

        vm.startPrank(tanssi);
        // Send initial collateral to the operators
        stETH.transfer(operator, OPERATOR_INITIAL_BALANCE);

        rETH.transfer(operator2, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator2, OPERATOR_INITIAL_BALANCE);

        stETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        rETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator3, OPERATOR_INITIAL_BALANCE);

        _deployVaults(tanssi);

        address operatorRewardsAddress =
            deployRewards.deployOperatorRewardsContract(tanssi, address(networkMiddlewareService), 5000, owner);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), operatorRewardsAddress, tanssi
        );
        stakerRewardsFactory = ODefaultStakerRewardsFactory(stakerRewardsFactoryAddress);

        middleware = _deployMiddlewareWithProxy(tanssi, owner, operatorRewardsAddress, stakerRewardsFactoryAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware));

        _createGateway();
        middleware.setGateway(address(gateway));
        middleware.setCollateralToOracle(address(stETH), stEthOracle);
        middleware.setCollateralToOracle(address(rETH), rEthOracle);
        middleware.setCollateralToOracle(address(wBTC), wBtcOracle);

        vetoSlasher = VetoSlasher(vaultAddresses.slasherVetoed);

        vetoSlasher.setResolver(0, resolver1, hex"");
        vetoSlasher.setResolver(0, resolver2, hex"");
        vm.stopPrank();

        vault = Vault(vaultAddresses.vault);
        vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        vaultVetoed = Vault(vaultAddresses.vaultVetoed);
        vaults.push(vault);
        vaults.push(vaultSlashable);
        vaults.push(vaultVetoed);

        _registerOperatorAndOptIn(operator, tanssi, address(vault), true);
        _registerOperatorAndOptIn(operator2, tanssi, address(vaultVetoed), true);
        _registerOperatorAndOptIn(operator2, tanssi, address(vaultSlashable), false);
        _registerOperatorAndOptIn(operator3, tanssi, address(vault), true);
        _registerOperatorAndOptIn(operator3, tanssi, address(vaultVetoed), false);
        _registerOperatorAndOptIn(operator3, tanssi, address(vaultSlashable), false);

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);

        _setLimitForNetworkAndOperators(tanssi);

        vm.startPrank(operator);
        _depositToVault(vault, operator, OPERATOR_STAKE_ST_ETH, stETH);

        vm.startPrank(operator2);
        _depositToVault(vaultSlashable, operator2, OPERATOR_STAKE_R_ETH, rETH);
        _depositToVault(vaultVetoed, operator2, OPERATOR_STAKE_BTC, wBTC);
        vm.stopPrank();

        vm.startPrank(operator3);
        _depositToVault(vault, operator3, OPERATOR_STAKE_ST_ETH, stETH);
        _depositToVault(vaultSlashable, operator3, OPERATOR_STAKE_R_ETH, rETH);
        _depositToVault(vaultVetoed, operator3, OPERATOR_STAKE_BTC, wBTC);

        totalFullRestakePower = (OPERATOR_STAKE_BTC * uint256(ORACLE_CONVERSION_W_BTC)) / 10 ** ORACLE_DECIMALS;

        totalPowerVault = (OPERATOR_STAKE_ST_ETH * 2 * uint256(ORACLE_CONVERSION_ST_ETH)) / 10 ** ORACLE_DECIMALS;
        totalPowerVaultSlashable = (OPERATOR_STAKE_R_ETH * 2 * uint256(ORACLE_CONVERSION_R_ETH)) / 10 ** ORACLE_DECIMALS;
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        HELPERS
    // ************************************************************************************************

    function _deployMiddlewareWithProxy(
        address _network,
        address _owner,
        address _operatorRewardsAddress,
        address _stakerRewardsFactoryAddress
    ) public returns (Middleware _middleware) {
        address readHelper = address(new OBaseMiddlewareReader());

        Middleware _middlewareImpl = new Middleware(_operatorRewardsAddress, _stakerRewardsFactoryAddress);
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: _network,
            operatorRegistry: address(operatorRegistry),
            vaultRegistry: address(vaultFactory),
            operatorNetworkOptIn: address(operatorNetworkOptInService),
            owner: _owner,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper
        });
        _middleware.initialize(params);

        networkMiddlewareService.setMiddleware(address(_middleware));
    }

    function _deployVaults(
        address _owner
    ) public {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(stETH),
            owner: _owner,
            operator: address(0),
            network: address(0)
        });

        (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) = deployVault.createBaseVault(params);

        params.collateral = address(rETH);
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);

        params.collateral = address(wBTC);
        params.delegatorIndex = VaultManager.DelegatorType.FULL_RESTAKE;

        (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
            deployVault.createVaultVetoed(params, 1 days);
    }

    function _depositToVault(Vault _vault, address _operator, uint256 _amount, Token collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        vm.startPrank(_owner);
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });
        middleware.registerSharedVault(vaultAddresses.vault, stakerRewardsParams);
        middleware.registerSharedVault(vaultAddresses.vaultSlashable, stakerRewardsParams);
        middleware.registerSharedVault(vaultAddresses.vaultVetoed, stakerRewardsParams);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        middleware.registerOperator(operator3, abi.encode(OPERATOR3_KEY), address(0));
        vm.stopPrank();
    }

    function _registerOperatorAndOptIn(address _operator, address _network, address _vault, bool firstTime) public {
        vm.startPrank(_operator);
        if (firstTime) {
            operatorRegistry.registerOperator();
            operatorNetworkOptInService.optIn(_network);
        }
        operatorVaultOptInService.optIn(address(_vault));
        vm.stopPrank();
    }

    function _setOperatorsNetworkShares(
        address _owner
    ) public {
        vm.startPrank(_owner);
        //The total shares are 3 (TOTAL_NETWORK_SHARE), so each operator has 1 share (OPERATOR_SHARE)
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );

        vm.stopPrank();
    }

    function _setLimitForNetworkAndOperators(
        address _owner
    ) public {
        vm.startPrank(_owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);

        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, OPERATOR_STAKE_BTC
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, OPERATOR_STAKE_BTC
        );
        vm.stopPrank();
    }

    /**
     * @param networkRestakePower The total stake of all operator vaults using NetworkRestake delegation
     * @param fullRestakePower The total stake of all operator vaults using FullRestake delegation
     * @param amountSlashed The amount slashed from the operator
     * @return totalOperatorPower
     * @return operatorPowerFromShares
     */
    function _calculateOperatorPower(
        uint256 networkRestakePower,
        uint256 fullRestakePower,
        uint256 amountSlashed
    ) public pure returns (uint256 totalOperatorPower, uint256 operatorPowerFromShares) {
        operatorPowerFromShares =
            _calculateRemainingStake(OPERATOR_SHARE, TOTAL_NETWORK_SHARES, networkRestakePower - amountSlashed);
        totalOperatorPower = operatorPowerFromShares + fullRestakePower;
    }

    function _calculateRemainingStake(
        uint256 sharesCount,
        uint256 totalShares,
        uint256 stake
    ) public pure returns (uint256) {
        return sharesCount.mulDiv(stake, totalShares);
    }

    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        assertEq(OBaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
        assertEq(OBaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY(), address(operatorRegistry));
        assertEq(OBaseMiddlewareReader(address(middleware)).VAULT_REGISTRY(), address(vaultFactory));
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(OBaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(OBaseMiddlewareReader(address(middleware)).subnetworksLength(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 3);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[1].vaults.length, 2);
        assertEq(operatorVaultPairs[2].vaults.length, 3);
    }

    function testOperatorsAreRegisteredAfterOneEpoch() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 3);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 3);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[1].vaults.length, 2);
        assertEq(operatorVaultPairs[2].vaults.length, 3);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 2);
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].power, validatorsPreviousEpoch[0].power);
        assertEq(validators[1].power, validatorsPreviousEpoch[1].power);
        assertEq(validators[2].power, validatorsPreviousEpoch[2].power);
        assertEq(validators[0].key, validatorsPreviousEpoch[0].key);
        assertEq(validators[1].key, validatorsPreviousEpoch[1].key);
        assertEq(validators[2].key, validatorsPreviousEpoch[2].key);
    }

    function testUnregisterOperatorButPastVaultsAreNotShown() public {
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        uint48 previousEpochStartTs = middleware.getEpochStart(previousEpoch);

        vm.startPrank(owner);
        address[] memory operatorVaults = OBaseMiddlewareReader(address(middleware)).activeVaults(operator2);
        assertEq(operatorVaults.length, 3);

        middleware.pauseOperator(operator2);
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator2);

        // Get validator set for current epoch
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);

        operatorVaults = OBaseMiddlewareReader(address(middleware)).activeVaults(operator2);

        uint256 operatorPower =
            OBaseMiddlewareReader(address(middleware)).getOperatorPowerAt(previousEpochStartTs, operator2);
        address[] memory previousActiveOperators =
            OBaseMiddlewareReader(address(middleware)).activeOperatorsAt(previousEpochStartTs);
        assertGt(operatorPower, 0);

        // Vaults history for the operators is kept intact
        assertEq(operatorVaults.length, 3);
        // Operators history is completely erased
        assertEq(previousActiveOperators.length, 2);

        assertEq(validators.length, 2);
        vm.stopPrank();
    }

    function testWithdraw() public {
        uint256 currentEpoch = vaultSlashable.currentEpoch();
        vm.prank(operator2);
        vaultSlashable.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = vaultSlashable.currentEpoch();
        vm.prank(operator2);
        vaultSlashable.claim(operator2, currentEpoch - 1);
        assertEq(rETH.balanceOf(operator2), OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE_ST_ETH + DEFAULT_WITHDRAW_AMOUNT);
    }

    function testOperatorPower() public {
        (, Middleware.ValidatorData[] memory validators, uint256 totalOperator2Power,, uint256 totalOperator3Power,) =
            _prepareSlashingTest();

        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations

        assertEq(validators[1].power, totalOperator2Power);
        assertEq(validators[2].power, totalOperator3Power);
    }

    function testSlashingOnOperator2AndVetoingSlash() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.prank(resolver1);
        vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingOnOperator2ButWrongSlashingWindow() public {
        vm.warp(NETWORK_EPOCH_DURATION * 2 + SLASHING_WINDOW / 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 epochStartTs = middleware.getEpochStart(currentEpoch);

        // We go directly to epochStart as it 100% ensure that the epoch is started and thus the slashing is invalid
        vm.warp(epochStartTs);

        vm.prank(gateway);
        vm.expectRevert(IVetoSlasher.InvalidCaptureTimestamp.selector);
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);
        vm.stopPrank();
    }

    function testSlashTooBig() public {
        vm.warp(NETWORK_EPOCH_DURATION * 2 + SLASHING_WINDOW / 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 epochStartTs = middleware.getEpochStart(currentEpoch);

        // We go directly to epochStart as it 100% ensure that the epoch is started and thus the slashing is invalid
        vm.warp(epochStartTs);

        // 150%
        uint256 slashingFraction = (3 * PARTS_PER_BILLION) / 2;

        vm.prank(gateway);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMiddleware.Middleware__SlashPercentageTooBig.selector, currentEpoch, operator2, slashingFraction
            )
        );
        middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);
    }

    function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + VETO_DURATION);
        middleware.executeSlash(address(vaultVetoed), 0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingOnOperator3AndVetoingSlash() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,, uint256 powerFromSharesOperator3) =
            _prepareSlashingTest();

        // We only take half of the operator3 shares, since only its participation on vaultSlashable will be slashed, regular vault isn't affected
        uint256 slashingPower = (SLASHING_FRACTION * (powerFromSharesOperator3 / 2)) / PARTS_PER_BILLION;

        vm.prank(gateway);
        middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

        vm.prank(resolver1);
        vetoSlasher.vetoSlash(0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingOnOperator3AndExecuteSlashOnVetoVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,, uint256 powerFromSharesOperator3) =
            _prepareSlashingTest();

        // We only take half of the operator3 shares, since only its participation on vaultSlashable will be slashed, regular vault isn't affected
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator3 / 2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + VETO_DURATION);
        middleware.executeSlash(address(vaultVetoed), 0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        // The first vault is not Slashable, so we calculate the power with no slashing
        (uint256 totalOperator3PowerFirstVault,) = _calculateOperatorPower(totalPowerVault, 0, 0);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter + totalOperator3PowerFirstVault);
    }

    function testSlashingAndPausingVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,,) = _prepareSlashingTest();

        vm.prank(owner);
        middleware.pauseSharedVault(vaultAddresses.vaultSlashable);

        vm.prank(gateway);
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) = _calculateOperatorPower(0, totalFullRestakePower, 0);
        (uint256 totalOperator3PowerAfter,) = _calculateOperatorPower(totalPowerVault, totalFullRestakePower, 0);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingAndPausingOperator() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        vm.prank(owner);
        middleware.pauseOperator(operator2);

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        //! Why this slash should anyway go through if operator was paused? Shouldn't it revert?
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        // Index is 1 instead of 2 because operator2 was paused
        assertEq(validators[1].power, totalOperator3PowerAfter);
    }

    function testSlashEvenIfWeChangeOperatorKey() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        // Everything below should be call with the owner key
        vm.startPrank(owner);

        // Before slashing, we will change the operator2 key to something else, and prove we can still slash
        // This is because operator keys work with timestamps and old keys are maintained, not removed
        // Therefore we will always be able to slash
        bytes32 differentOperatorKey = bytes32(uint256(10));
        middleware.updateOperatorKey(operator2, abi.encode(differentOperatorKey));

        vm.startPrank(gateway);
        middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.startPrank(resolver1);
        vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testOperatorsOnlyInTanssiNetwork() public {
        address operatorX = makeAddr("operatorX");
        address network2 = makeAddr("network2");
        bytes32 OPERATORX_KEY = bytes32(uint256(4));

        //Middleware 2 Deployment
        vm.startPrank(network2);
        networkRegistry.registerNetwork();
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);

        vm.startPrank(owner);
        stETH.transfer(operatorX, OPERATOR_INITIAL_BALANCE);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            network2.subnetwork(0), operatorX, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(network2.subnetwork(0), 300 ether);

        // OperatorX registration and network configuration
        _registerOperatorAndOptIn(operatorX, network2, address(vault), true);

        address operatorRewardsAddress2 =
            deployRewards.deployOperatorRewardsContract(network2, address(networkMiddlewareService), 5000, owner);

        vm.startPrank(network2);
        Middleware middleware2 =
            _deployMiddlewareWithProxy(network2, network2, operatorRewardsAddress2, address(stakerRewardsFactory));

        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: network2,
            adminFeeClaimRoleHolder: network2,
            adminFeeSetRoleHolder: network2
        });
        vm.startPrank(owner);
        ODefaultOperatorRewards operatorRewards2 = ODefaultOperatorRewards(operatorRewardsAddress2);
        operatorRewards2.grantRole(operatorRewards2.MIDDLEWARE_ROLE(), address(middleware2));
        operatorRewards2.grantRole(operatorRewards2.STAKER_REWARDS_SETTER_ROLE(), address(middleware2));

        vm.startPrank(network2);
        middleware2.registerSharedVault(address(vault), stakerRewardsParams);
        middleware2.registerOperator(operatorX, abi.encode(OPERATORX_KEY), address(0));

        vm.stopPrank();

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 middleware2CurrentEpoch = middleware2.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operator2VaultPairs =
            OBaseMiddlewareReader(address(middleware2)).getOperatorVaultPairs(middleware2CurrentEpoch);
        assertEq(operator2VaultPairs.length, 1);
        assertEq(operator2VaultPairs[0].operator, operatorX);
        assertEq(operator2VaultPairs[0].vaults.length, 1);
        uint48 middlewareCurrentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(middlewareCurrentEpoch);
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            assert(operatorVaultPairs[i].operator != operatorX);
        }
    }

    function testCollateralsWithDifferentDecimals() public {
        vm.startPrank(owner);

        Token usdc = Token(deployCollateral.deployCollateral("usdc", USDC_TOKEN_DECIMALS));
        Token usdt = Token(deployCollateral.deployCollateral("usdt", USDT_TOKEN_DECIMALS));

        usdc.mint(operator4, 1000 * 10 ** USDC_TOKEN_DECIMALS);
        usdc.mint(operator5, 1000 * 10 ** USDC_TOKEN_DECIMALS);
        usdt.mint(operator4, 1000 * 10 ** USDT_TOKEN_DECIMALS);
        usdt.mint(operator5, 1000 * 10 ** USDT_TOKEN_DECIMALS);

        address usdcOracle = _deployOracle(USDC_ORACLE_DECIMALS, int256(1 * 10 ** USDC_ORACLE_DECIMALS));
        address usdtOracle = _deployOracle(USDT_ORACLE_DECIMALS, int256(1 * 10 ** USDT_ORACLE_DECIMALS));

        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(usdc),
            owner: tanssi,
            operator: address(0),
            network: address(0)
        });

        (address vaultUsdc, address vaultDelegatorUsdc,) = deployVault.createBaseVault(params);

        params.collateral = address(usdt);
        (address vaultUsdt, address vaultDelegatorUsdt,) = deployVault.createBaseVault(params);

        middleware.setCollateralToOracle(address(usdc), usdcOracle);
        middleware.setCollateralToOracle(address(usdt), usdtOracle);

        _registerOperatorAndOptIn(operator4, tanssi, address(vaultUsdc), true);
        _registerOperatorAndOptIn(operator4, tanssi, address(vaultUsdt), false);

        _registerOperatorAndOptIn(operator5, tanssi, address(vaultUsdc), true);
        _registerOperatorAndOptIn(operator5, tanssi, address(vaultUsdt), false);

        vm.startPrank(owner);

        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });
        middleware.registerSharedVault(vaultUsdc, stakerRewardsParams);
        middleware.registerSharedVault(vaultUsdt, stakerRewardsParams);

        middleware.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
        middleware.registerOperator(operator5, abi.encode(OPERATOR5_KEY), address(0));

        vm.startPrank(tanssi);

        INetworkRestakeDelegator(vaultDelegatorUsdc).setOperatorNetworkShares(tanssi.subnetwork(0), operator4, 1);
        INetworkRestakeDelegator(vaultDelegatorUsdc).setOperatorNetworkShares(tanssi.subnetwork(0), operator5, 1);

        INetworkRestakeDelegator(vaultDelegatorUsdt).setOperatorNetworkShares(tanssi.subnetwork(0), operator4, 1);
        INetworkRestakeDelegator(vaultDelegatorUsdt).setOperatorNetworkShares(tanssi.subnetwork(0), operator5, 1);

        INetworkRestakeDelegator(vaultDelegatorUsdc).setMaxNetworkLimit(0, 1000 * 10 ** USDC_ORACLE_DECIMALS);
        INetworkRestakeDelegator(vaultDelegatorUsdt).setMaxNetworkLimit(0, 1000 * 10 ** USDT_ORACLE_DECIMALS);

        INetworkRestakeDelegator(vaultDelegatorUsdc).setNetworkLimit(
            tanssi.subnetwork(0), 1000 * 10 ** USDC_ORACLE_DECIMALS
        );
        INetworkRestakeDelegator(vaultDelegatorUsdt).setNetworkLimit(
            tanssi.subnetwork(0), 1000 * 10 ** USDT_ORACLE_DECIMALS
        );

        vm.startPrank(operator4);
        _depositToVault(Vault(vaultUsdc), operator4, OPERATOR_4_STAKE_USDC, usdc);
        _depositToVault(Vault(vaultUsdt), operator4, OPERATOR_4_STAKE_USDT, usdt);

        vm.startPrank(operator5);
        _depositToVault(Vault(vaultUsdc), operator5, OPERATOR_5_STAKE_USDC, usdc);
        _depositToVault(Vault(vaultUsdt), operator5, OPERATOR_5_STAKE_USDT, usdt);

        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = _validatorSet(currentEpoch);

        // Total deposit is 300 USD, it should be normalized to 18 decimals
        uint256 totalPowerByShares = 300 ether;
        // Only 2 operators participate in the USD vaults, so each has half of the power.
        uint256 totalPowerOperator = totalPowerByShares / 2;

        assertEq(validators[3].power, totalPowerOperator);
        assertEq(validators[4].power, totalPowerOperator);
    }

    function _createGateway() internal returns (address) {
        ParaID bridgeHubParaID = ParaID.wrap(1013);
        bytes32 bridgeHubAgentID = 0x03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314;

        ParaID assetHubParaID = ParaID.wrap(1000);
        bytes32 assetHubAgentID = 0x81c5ab2571199e3188135178f3c2c8e2d268be1313d029b30f534fa579b69b79;

        GatewayParams memory params = GatewayParams({
            operatingMode: OperatingMode.Normal,
            outboundFee: 1e10,
            registerTokenFee: 0,
            sendTokenFee: 1e10,
            createTokenFee: 1e10,
            maxDestinationFee: 1e11,
            foreignTokenDecimals: 10,
            exchangeRate: ud60x18(0.0025e18),
            multiplier: ud60x18(1e18),
            assetHubParaID: assetHubParaID,
            assetHubAgentID: assetHubAgentID
        });

        AgentExecutor executor = new AgentExecutor();
        MockOGateway gatewayLogic = new MockOGateway(
            address(0),
            address(executor),
            bridgeHubParaID,
            bridgeHubAgentID,
            params.foreignTokenDecimals,
            params.maxDestinationFee
        );
        Gateway.Config memory config = Gateway.Config({
            mode: OperatingMode.Normal,
            deliveryCost: params.outboundFee,
            registerTokenFee: params.registerTokenFee,
            assetHubParaID: params.assetHubParaID,
            assetHubAgentID: params.assetHubAgentID,
            assetHubCreateAssetFee: params.createTokenFee,
            assetHubReserveTransferFee: params.sendTokenFee,
            exchangeRate: params.exchangeRate,
            multiplier: params.multiplier,
            rescueOperator: 0x4B8a782D4F03ffcB7CE1e95C5cfe5BFCb2C8e967
        });
        gateway = address(new GatewayProxy(address(gatewayLogic), abi.encode(config)));
        MockGateway(address(gateway)).setCommitmentsAreVerified(true);

        SetOperatingModeParams memory operatingModeParams = SetOperatingModeParams({mode: OperatingMode.Normal});
        MockGateway(address(gateway)).setOperatingModePublic(abi.encode(operatingModeParams));
        IOGateway(address(gateway)).setMiddleware(address(middleware));
        return address(gateway);
    }

    function _createParaIDAndAgent(
        IOGateway _gateway
    ) public returns (ParaID) {
        ParaID paraID = ParaID.wrap(1);
        bytes32 agentID = keccak256("1");

        MockGateway(address(_gateway)).createAgentPublic(abi.encode(CreateAgentParams({agentID: agentID})));

        CreateChannelParams memory params =
            CreateChannelParams({channelID: paraID.into(), agentID: agentID, mode: OperatingMode.Normal});

        MockGateway(address(_gateway)).createChannelPublic(abi.encode(params));
        return paraID;
    }

    function _addOperatorsToNetwork(
        uint256 _count
    ) public {
        for (uint256 i = 0; i < _count; i++) {
            address _operator = makeAddr(string.concat("operator", Strings.toString(i + 4)));
            address _vault = address(vault);
            address _delegator = address(vaultAddresses.delegator);
            Token token = stETH;
            vm.startPrank(owner);
            if (i % 3 == 0) {
                _vault = address(vaultSlashable);
                _delegator = address(vaultAddresses.delegatorSlashable);
                rETH.transfer(_operator, 1 ether);
                token = rETH;
            } else if (i % 3 == 1) {
                _vault = address(vaultVetoed);
                _delegator = address(vaultAddresses.delegatorVetoed);
                wBTC.transfer(_operator, 1 ether);
                token = wBTC;
            } else {
                stETH.transfer(_operator, 1 ether);
            }
            _registerOperatorAndOptIn(_operator, tanssi, address(_vault), true);
            vm.startPrank(_operator);
            uint256 depositAmount = 0.001 ether * (i + 1);
            _depositToVault(Vault(_vault), _operator, depositAmount, token);

            vm.startPrank(owner);
            if (i % 3 == 1) {
                // FULL_RESTAKE, needs to set the operator network limit
                IFullRestakeDelegator(_delegator).setOperatorNetworkLimit(
                    tanssi.subnetwork(0), _operator, OPERATOR_STAKE_BTC
                );
            } else {
                // NETWORK_RESTAKE, needs to set the operator network shares
                INetworkRestakeDelegator(_delegator).setOperatorNetworkShares(
                    tanssi.subnetwork(0), _operator, OPERATOR_SHARE
                );
            }
            bytes32 operatorKey = bytes32(uint256(i + 4));
            middleware.registerOperator(_operator, abi.encode(operatorKey), address(0));
            vm.stopPrank();
        }
    }

    function quickSort(Middleware.ValidatorData[] memory arr, int256 left, int256 right) public pure {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].power;
        while (i <= j) {
            while (arr[uint256(i)].power > pivot) i++;
            while (pivot > arr[uint256(j)].power) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (arr[uint256(j)], arr[uint256(i)]);
                i++;
                j--;
            }
        }
        if (left < j) {
            quickSort(arr, left, j);
        }
        if (i < right) {
            quickSort(arr, i, right);
        }
    }

    function _validatorSet(
        uint48 epoch
    ) public view returns (Middleware.ValidatorData[] memory) {
        Middleware.ValidatorData[] memory validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(epoch);
        quickSort(validators, 0, int256(validators.length - 1));
        return validators;
    }

    function _assertDataIsValidAndSorted(
        Middleware.ValidatorData[] memory validators,
        bytes32[] memory sortedValidators,
        uint16 count
    ) public pure {
        assertEq(validators.length, count + 3);
        assertEq(validators.length, sortedValidators.length);
        for (uint256 i = 0; i < validators.length - 1; i++) {
            if (i != 0 && i < count - 1) {
                assertLe(validators[i].power, validators[i - 1].power);
            }
        }
        for (uint256 i = 0; i < sortedValidators.length - 1; i++) {
            if (i != 0 && i < count - 1) {
                assertEq(validators[i].key, sortedValidators[i]);
            }
        }
    }

    function testGasFor10OperatorsIn3VaultsSorted() public {
        uint16 count = 100;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = _validatorSet(currentEpoch);

        uint256 gasBefore = gasleft();
        bytes32[] memory sortedValidators =
            OBaseMiddlewareReader(address(middleware)).sortOperatorsByPower(currentEpoch);
        uint256 gasAfter = gasleft();

        uint256 gasSorted = gasBefore - gasAfter;
        console2.log("Total gas used: ", gasSorted);

        _assertDataIsValidAndSorted(validators, sortedValidators, count);
    }

    function testGasFor100peratorsIn3VaultsNonSorted() public {
        uint16 count = 100;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasNotSorted = gasBefore - gasAfter;
        console2.log("Total gas used for non sorted: ", gasNotSorted);
    }

    function testGasFor25OperatorsIn3VaultsSorted() public {
        uint16 count = 250;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        bytes32[] memory sortedValidators =
            OBaseMiddlewareReader(address(middleware)).sortOperatorsByPower(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasSorted = gasBefore - gasAfter;
        console2.log("Total gas used: ", gasSorted);

        Middleware.ValidatorData[] memory validators = _validatorSet(currentEpoch);
        _assertDataIsValidAndSorted(validators, sortedValidators, count);
    }

    function testGasFor20OperatorsIn3VaultsNonSorted() public {
        uint16 count = 250;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasNotSorted = gasBefore - gasAfter;
        console2.log("Total gas used for non sorted: ", gasNotSorted);
    }

    function testGasFor30OperatorsIn3VaultsSorted() public {
        uint16 count = 350;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        bytes32[] memory sortedValidators =
            OBaseMiddlewareReader(address(middleware)).sortOperatorsByPower(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasSorted = gasBefore - gasAfter;
        console2.log("Total gas used: ", gasSorted);

        Middleware.ValidatorData[] memory validators = _validatorSet(currentEpoch);
        _assertDataIsValidAndSorted(validators, sortedValidators, count);
    }

    function testGasFor30OperatorsIn3VaultsNonSorted() public {
        uint16 count = 350;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasNotSorted = gasBefore - gasAfter;
        console2.log("Total gas used for non sorted: ", gasNotSorted);
    }

    function testGasFor50OperatorsIn3VaultsNonSorted() public {
        uint16 count = 500;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasNotSorted = gasBefore - gasAfter;
        console2.log("Total gas used for non sorted: ", gasNotSorted);
    }

    function testGasFor50OperatorsIn3VaultsSorted() public {
        uint16 count = 500;
        _addOperatorsToNetwork(count);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        uint256 gasBefore = gasleft();
        bytes32[] memory sortedValidators =
            OBaseMiddlewareReader(address(middleware)).sortOperatorsByPower(currentEpoch);
        uint256 gasAfter = gasleft();
        uint256 gasSorted = gasBefore - gasAfter;
        console2.log("Total gas used: ", gasSorted);

        Middleware.ValidatorData[] memory validators = _validatorSet(currentEpoch);

        _assertDataIsValidAndSorted(validators, sortedValidators, count);
    }

    // ************************************************************************************************
    // *                                        UPKEEP
    // ************************************************************************************************

    function testUpkeep() public {
        vm.prank(owner);
        middleware.setForwarder(forwarder);
        // It's not needed, it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");
        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        vm.startPrank(forwarder);
        middleware.performUpkeep(performData);
        uint48 epoch = middleware.getCurrentEpoch();

        uint256 operator1Power = middleware.getOperatorToPower(epoch, OPERATOR_KEY);
        uint256 operator2Power = middleware.getOperatorToPower(epoch, OPERATOR2_KEY);
        uint256 operator3Power = middleware.getOperatorToPower(epoch, OPERATOR3_KEY);

        (uint256 totalOperatorPowerAfter,) = _calculateOperatorPower(totalPowerVault, 0, 0);
        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, 0);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, 0);

        assertEq(operator1Power, totalOperatorPowerAfter);
        assertEq(operator2Power, totalOperator2PowerAfter);
        assertEq(operator3Power, totalOperator3PowerAfter);

        vm.startPrank(offlineKeepers);
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        (uint8 command, bytes32[] memory sortedKeys) = abi.decode(performData, (uint8, bytes32[]));
        assertEq(command, middleware.SEND_DATA_COMMAND());

        vm.startPrank(forwarder);
        vm.expectEmit(true, false, false, false);
        emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
        middleware.performUpkeep(performData);

        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);
        assertEq(performData.length, 0);
    }

    function testUpkeepFor100OperatorsIn3VaultsSorted() public {
        uint16 count = 100;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        // This will exhaust and fill the cache in n (count/max_operators_to_process) times
        uint256 totalGasUsedForCheck = 0;
        uint256 totalGasUsedForPerform = 0;
        {
            uint256 max = middleware.MAX_OPERATORS_TO_PROCESS();
            for (uint256 i = 0; i < (count + max - 1) / max; i++) {
                uint256 gasBeforeCheck = gasleft();
                (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
                uint256 gasAfterCheck = gasleft();
                uint256 gasUsedCheck = gasBeforeCheck - gasAfterCheck;
                totalGasUsedForCheck += gasUsedCheck;

                console2.log("Gas used for check: ", gasUsedCheck);
                assertEq(upkeepNeeded, true);

                vm.startPrank(forwarder);
                uint256 gasBeforePerform = gasleft();
                middleware.performUpkeep(performData);
                uint256 gasAfterPerform = gasleft();
                uint256 gasUsedPerform = gasBeforePerform - gasAfterPerform;
                totalGasUsedForPerform += gasUsedPerform;
                console2.log("Gas used for perform: ", gasUsedPerform);
            }
        }

        // After the loop, we should have all operators processed and cache filled
        // Now the keepers will call performUpkeep with the cache and sending the operators keys to the gateway
        uint256 gasBeforeFinalCheck = gasleft();
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        uint256 gasAfterFinalCheck = gasleft();
        uint256 gasUsedFinalCheck = gasBeforeFinalCheck - gasAfterFinalCheck;
        totalGasUsedForCheck += gasUsedFinalCheck;
        console2.log("Gas used for final check: ", gasUsedFinalCheck);
        assertEq(upkeepNeeded, true);

        (uint8 command, bytes32[] memory sortedKeys) = abi.decode(performData, (uint8, bytes32[]));
        assertEq(command, middleware.SEND_DATA_COMMAND());
        assertEq(sortedKeys.length, count);

        {
            vm.startPrank(forwarder);
            vm.expectEmit(true, false, false, false);
            emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
            uint256 gasBeforeFinalPerform = gasleft();
            middleware.performUpkeep(performData);
            uint256 gasAfterFinalPerform = gasleft();
            uint256 gasUsedFinalPerform = gasBeforeFinalPerform - gasAfterFinalPerform;
            totalGasUsedForPerform += gasUsedFinalPerform;
            console2.log("Gas used for final perform: ", gasUsedFinalPerform);
        }

        console2.log("Total gas used for check: ", totalGasUsedForCheck);
        console2.log("Total gas used for perform: ", totalGasUsedForPerform);
        console2.log("Total gas used for upkeep: ", totalGasUsedForCheck + totalGasUsedForPerform);
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        vm.roll(50);
        uint256 gasBefore = gasleft();
        bytes32[] memory sortedValidators = middleware.sendCurrentOperatorsKeys();
        uint256 gasAfter = gasleft();
        uint256 gasSorted = gasBefore - gasAfter;
        console2.log("Total gas used for sorting manually: ", gasSorted);
    }

    function testUpkeepPerformDataShouldBeBelow2000Bytes() public {
        uint16 count = 37;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);

        uint256 max = middleware.MAX_OPERATORS_TO_PROCESS();
        for (uint256 i = 0; i < (count + max - 1) / max; i++) {
            (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
            assertEq(upkeepNeeded, true);
            console2.log("Perform Data length while caching: ", performData.length);
            assertLe(performData.length, 2000);

            vm.startPrank(forwarder);
            middleware.performUpkeep(performData);
        }

        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);
        console2.log("Perform Data length while sending: ", performData.length);
        assertLe(performData.length, 2000);

        (uint8 command, bytes32[] memory sortedKeys) = abi.decode(performData, (uint8, bytes32[]));
        assertEq(command, middleware.SEND_DATA_COMMAND());
        assertEq(sortedKeys.length, count);
        assertLe(performData.length, 2000);

        vm.startPrank(forwarder);
        middleware.performUpkeep(performData);
    }

    function testUpkeepShouldFailDueToWrongCacheCommand() public {
        uint16 count = 37;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);

        uint256 max = middleware.MAX_OPERATORS_TO_PROCESS();
        for (uint256 i = 0; i < (count + max - 1) / max; i++) {
            (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
            assertEq(upkeepNeeded, true);

            vm.startPrank(forwarder);
            middleware.performUpkeep(performData);
        }

        vm.expectRevert(
            abi.encodeWithSelector(IMiddleware.Middleware__InvalidCommand.selector, middleware.CACHE_DATA_COMMAND())
        );
        middleware.performUpkeep(performData);
    }

    function testUpkeepShouldFailDueToWrongSendCommand() public {
        uint16 count = 37;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);

        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, true);

        (uint8 command, IMiddleware.ValidatorData[] memory data) =
            abi.decode(performData, (uint8, IMiddleware.ValidatorData[]));
        assertEq(command, middleware.CACHE_DATA_COMMAND());

        performData = abi.encode(middleware.SEND_DATA_COMMAND(), data);

        vm.startPrank(forwarder);
        vm.expectRevert(
            abi.encodeWithSelector(IMiddleware.Middleware__InvalidCommand.selector, middleware.SEND_DATA_COMMAND())
        );
        middleware.performUpkeep(performData);
    }

    function testUpkeepShouldFailToDecodeIfUsingValidatorsKeysInsteadOfValidatorsData() public {
        uint16 count = 37;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);

        uint256 max = middleware.MAX_OPERATORS_TO_PROCESS();
        for (uint256 i = 0; i < (count + max - 1) / max; i++) {
            (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
            assertEq(upkeepNeeded, true);

            vm.startPrank(forwarder);
            middleware.performUpkeep(performData);
        }

        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);

        vm.expectRevert();
        middleware.performUpkeep(performData);
    }

    function testUpkeepCacheIsAlwaysLessOrEqualThanActiveOperators() public {
        uint16 count = 100;
        _addOperatorsToNetwork(count);
        count += 3; // 3 operators are already registered
        vm.prank(owner);
        middleware.setForwarder(forwarder);

        address offlineKeepers = makeAddr("offlineKeepers");

        vm.startPrank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 epoch = middleware.getCurrentEpoch();
        uint256 activeOperatorsLength = (OBaseMiddlewareReader(address(middleware)).activeOperators()).length;
        {
            uint256 max = middleware.MAX_OPERATORS_TO_PROCESS();
            for (uint256 i = 0; i < (count + max - 1) / max; i++) {
                (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");

                uint256 cacheIndex = middleware.getEpochCacheIndex(epoch);
                assertGe(activeOperatorsLength, cacheIndex);
                assertEq(upkeepNeeded, true);

                vm.startPrank(forwarder);
                middleware.performUpkeep(performData);
            }
        }
    }

    function testWhenRegisteringVaultThenStakerRewardsAreDeployed() public {
        vm.startPrank(owner);
        uint256 totalEntities = stakerRewardsFactory.totalEntities();

        VaultAddresses memory testVaultAddresses = _createTestVault(owner);
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });

        middleware.registerSharedVault(testVaultAddresses.vault, stakerRewardsParams);
        vm.stopPrank();

        address stakerRewards = operatorRewards.vaultToStakerRewardsContract(testVaultAddresses.vault);
        // Check that the staker rewards contract is correctly and added to entities:
        assertEq(stakerRewardsFactory.totalEntities(), totalEntities + 1);
        assertNotEq(stakerRewards, address(0));

        // Check that the staker rewards contract is correctly configured:
        ODefaultStakerRewards stakerRewardsContract = ODefaultStakerRewards(stakerRewards);
        assertEq(stakerRewardsContract.i_vault(), testVaultAddresses.vault);
        assertEq(stakerRewardsContract.i_network(), tanssi);
        assertTrue(stakerRewardsContract.hasRole(stakerRewardsContract.DEFAULT_ADMIN_ROLE(), tanssi));
        assertTrue(stakerRewardsContract.hasRole(stakerRewardsContract.ADMIN_FEE_CLAIM_ROLE(), tanssi));
        assertTrue(stakerRewardsContract.hasRole(stakerRewardsContract.ADMIN_FEE_SET_ROLE(), tanssi));
        assertTrue(
            stakerRewardsContract.hasRole(stakerRewardsContract.OPERATOR_REWARDS_ROLE(), address(operatorRewards))
        );
    }

    function _createTestVault(
        address _owner
    ) public returns (VaultAddresses memory testVaultAddresses) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(stETH),
            owner: _owner,
            operator: address(0),
            network: address(0)
        });

        (testVaultAddresses.vault, testVaultAddresses.delegator, testVaultAddresses.slasher) =
            deployVault.createBaseVault(params);

        return testVaultAddresses;
    }

    function _prepareSlashingTest()
        public
        returns (
            uint48 currentEpoch,
            Middleware.ValidatorData[] memory validators,
            uint256 totalOperator2Power,
            uint256 powerFromSharesOperator2,
            uint256 totalOperator3Power,
            uint256 powerFromSharesOperator3
        )
    {
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        currentEpoch = middleware.getCurrentEpoch();

        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);

        (totalOperator2Power, powerFromSharesOperator2) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, 0);
        (totalOperator3Power, powerFromSharesOperator3) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, 0);
    }

    function _deployOracle(uint8 decimals, int256 answer) public returns (address) {
        MockV3Aggregator oracle = new MockV3Aggregator(decimals, answer);
        return address(oracle);
    }

    // ************************************************************************************************
    // *                                  SEND CURRENT OPERATORS KEYS
    // ************************************************************************************************

    function testSendCurrentOperatorKeysOrderChangesIfPowerChanges() public {
        vm.mockCall(address(gateway), abi.encodeWithSelector(IOGateway.sendOperatorsData.selector), new bytes(0));

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        vm.roll(80);
        bytes32[] memory keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 3);

        // OP3 > OP2 > OP1 (In terms of power)
        assertEq(keys[0], OPERATOR3_KEY);
        assertEq(keys[1], OPERATOR2_KEY);
        assertEq(keys[2], OPERATOR_KEY);

        vm.startPrank(owner);
        // This doesn't remove operator3's stake, but turns his power to zero, so it is not only the top operator.
        // Withdrawing would not change the order since this vault is full restake giving both OP3 and OP2 the same power.
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, 0
        );

        vm.warp(block.timestamp + VAULT_EPOCH_DURATION + 1);
        vm.roll(80 + 57_235); // 57_235 is ≈ the number of blocks in 1 week
        keys = middleware.sendCurrentOperatorsKeys();
        assertEq(keys.length, 3);

        // Now OP2 > OP3 > OP1 (In terms of power)
        assertEq(keys[0], OPERATOR2_KEY);
        assertEq(keys[1], OPERATOR3_KEY);
        assertEq(keys[2], OPERATOR_KEY);
    }
}
