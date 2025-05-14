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
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {KeyManagerAddress} from "@symbiotic-middleware/extensions/managers/keys/KeyManagerAddress.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";
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
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {OperatingMode, ParaID} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Types.sol";
import {MockGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockGateway.sol";
import {GatewayProxy} from "@tanssi-bridge-relayer/snowbridge/contracts/src/GatewayProxy.sol";
import {AgentExecutor} from "@tanssi-bridge-relayer/snowbridge/contracts/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {Gateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Gateway.sol";
import {MockOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockOGateway.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {Token} from "test/mocks/Token.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 7 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 2 days;
    uint48 public constant SLASHING_WINDOW = 5 days;
    uint48 public constant VETO_DURATION = 1 days;

    // Token and Oracle decimals + conversion rates
    uint8 public constant TOKEN_DECIMALS_BTC = 18;
    uint8 public constant TOKEN_DECIMALS_ETH = 18;
    uint8 public constant TOKEN_DECIMALS_USDC = 6;

    uint8 public constant ORACLE_DECIMALS_ETH = 2;
    uint8 public constant ORACLE_DECIMALS_BTC = 2;
    uint8 public constant ORACLE_DECIMALS_USDC = 8;

    int256 public constant ORACLE_CONVERSION_ST_ETH = int256(3000 * 10 ** ORACLE_DECIMALS_ETH);
    int256 public constant ORACLE_CONVERSION_W_BTC = int256(90_000 * 10 ** ORACLE_DECIMALS_BTC);
    int256 public constant ORACLE_CONVERSION_USDC = int256(1 * 10 ** ORACLE_DECIMALS_USDC);

    uint48 public constant OPERATOR_SHARE = 1000; // 10%
    uint48 public constant MAX_PERCENTAGE = 10_000;
    uint48 public constant ADMIN_FEE = 100; // 1%

    // Operator keys
    bytes32 public constant OPERATOR1_KEY = 0x0101010101010101010101010101010101010101010101010101010101010101;
    bytes32 public constant OPERATOR2_KEY = 0x0202020202020202020202020202020202020202020202020202020202020202;
    bytes32 public constant OPERATOR3_KEY = 0x0303030303030303030303030303030303030303030303030303030303030303;
    bytes32 public constant OPERATOR4_KEY = 0x0404040404040404040404040404040404040404040404040404040404040404;
    bytes32 public constant OPERATOR5_KEY = 0x0505050505050505050505050505050505050505050505050505050505050505;
    bytes32 public constant OPERATOR6_KEY = 0x0606060606060606060606060606060606060606060606060606060606060606;
    bytes32 public constant OPERATOR7_KEY = 0x0707070707070707070707070707070707070707070707070707070707070707;
    bytes32 public constant OPERATOR8_KEY = 0x0808080808080808080808080808080808080808080808080808080808080808;
    bytes32 public constant OPERATOR9_KEY = 0x0909090909090909090909090909090909090909090909090909090909090909;

    // Vault 1 - Single Operator
    uint256 public constant VAULT1_NETWORK_LIMIT = 500_000 * 10 ** TOKEN_DECIMALS_USDC; // 500k power
    uint256 public constant OPERATOR1_STAKE_V1_USDC = 100_000 * 10 ** TOKEN_DECIMALS_USDC; // 100k power

    // Vault 2 - 3 Operators, Full Restake
    uint256 public constant VAULT2_NETWORK_LIMIT = 10 * 10 ** TOKEN_DECIMALS_BTC; // 900k power
    uint256 public constant OPERATOR1_STAKE_V2_WBTC = 2 * 10 ** TOKEN_DECIMALS_BTC; // 180k power
    uint256 public constant OPERATOR2_STAKE_V2_WBTC = 1 * 10 ** TOKEN_DECIMALS_BTC; // 90k power
    uint256 public constant OPERATOR3_STAKE_V2_WBTC = 3 * 10 ** TOKEN_DECIMALS_BTC; // 270k power
    uint256 public constant VAULT2_TOTAL_STAKE =
        OPERATOR1_STAKE_V2_WBTC + OPERATOR2_STAKE_V2_WBTC + OPERATOR3_STAKE_V2_WBTC;

    // Limits are set by stake, not power
    uint256 public constant OPERATOR1_LIMIT_V2 = 2 * 10 ** TOKEN_DECIMALS_BTC; // Limited to 2 BTC
    uint256 public constant OPERATOR2_LIMIT_V2 = 2 * 10 ** TOKEN_DECIMALS_BTC; // Limited to 2 BTC
    uint256 public constant OPERATOR3_LIMIT_V2 = 2 * 10 ** TOKEN_DECIMALS_BTC; // Limited to 2 BTC

    // Vault 3 - 3 Operators, Network Restake (by Shares)
    uint256 public constant VAULT3_NETWORK_LIMIT = 10 * 10 ** TOKEN_DECIMALS_BTC; // 900k power
    uint256 public constant OPERATOR3_STAKE_V3_WBTC = 1 * 10 ** TOKEN_DECIMALS_BTC; // 90k power
    uint256 public constant OPERATOR4_STAKE_V3_WBTC = 2 * 10 ** TOKEN_DECIMALS_BTC; // 180k power
    uint256 public constant OPERATOR5_STAKE_V3_WBTC = 2 * 10 ** TOKEN_DECIMALS_BTC; // 180k power
    uint256 public constant VAULT3_TOTAL_STAKE =
        OPERATOR3_STAKE_V3_WBTC + OPERATOR4_STAKE_V3_WBTC + OPERATOR5_STAKE_V3_WBTC;

    uint256 public constant OPERATOR3_SHARES_V3 = 1; // Operator 3 will get 20% of the total power
    uint256 public constant OPERATOR4_SHARES_V3 = 2; // Operator 4 will get 40% of the total power
    uint256 public constant OPERATOR5_SHARES_V3 = 2; // Operator 5 will get 40% of the total power
    uint256 public constant VAULT3_TOTAL_SHARES = OPERATOR3_SHARES_V3 + OPERATOR4_SHARES_V3 + OPERATOR5_SHARES_V3;

    // Vault 4 - 2 Operators, Network Restake (by Shares)
    uint256 public constant VAULT4_NETWORK_LIMIT = 100 * 10 ** TOKEN_DECIMALS_ETH; // 300k power
    uint256 public constant OPERATOR5_STAKE_V4_STETH = 50 * 10 ** TOKEN_DECIMALS_ETH; // 150k power
    uint256 public constant OPERATOR6_STAKE_V4_STETH = 30 * 10 ** TOKEN_DECIMALS_ETH; // 90k power
    uint256 public constant VAULT4_TOTAL_STAKE = OPERATOR5_STAKE_V4_STETH + OPERATOR6_STAKE_V4_STETH;

    uint256 public constant OPERATOR5_SHARES_V4 = 2; // Operator 5 will get 2/3 of the total power
    uint256 public constant OPERATOR6_SHARES_V4 = 1; // Operator 6 will get 1/3 of the total power
    uint256 public constant VAULT4_TOTAL_SHARES = OPERATOR5_SHARES_V4 + OPERATOR6_SHARES_V4;

    // Vault 5 - Single Operator + Single Network
    uint256 public constant VAULT5_NETWORK_LIMIT = 200 * 10 ** TOKEN_DECIMALS_ETH; // 200k power
    uint256 public constant OPERATOR7_STAKE_V5_STETH = 100 * 10 ** TOKEN_DECIMALS_ETH; // 100k power

    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 10; // 10%

    struct VaultsData {
        VaultData v1;
        VaultData v2;
        VaultData v3;
        VaultData v4;
        VaultData v5;
    }

    struct VaultData {
        IVault vault;
        address delegator;
        address slasher;
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
    OBaseMiddlewareReader public middlewareReader;
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
    Token public usdc;
    Token public wBTC;
    Token public stETH;
    Token public STAR;
    VaultConfigurator public vaultConfigurator;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);

    address public operator1 = makeAddr("operator1");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public operator4 = makeAddr("operator4");
    address public operator5 = makeAddr("operator5");
    address public operator6 = makeAddr("operator6");
    address public operator7 = makeAddr("operator7");

    address public resolver1 = makeAddr("resolver1"); // For Vault 4
    address public resolver2 = makeAddr("resolver2"); // For Vault 5
    address public forwarder = makeAddr("forwarder");

    address tanssi;
    address gateway;

    VaultsData public vaultsData;

    // // Scripts
    DeployVault deployVault;
    DeployRewards deployRewards;
    ODefaultOperatorRewards operatorRewards;
    ODefaultStakerRewardsFactory stakerRewardsFactory;

    // ************************************************************************************************
    // *                                        SETUP
    // ************************************************************************************************

    function setUp() public {
        _deployTokens();

        address usdcOracle = _deployOracle(ORACLE_DECIMALS_USDC, ORACLE_CONVERSION_USDC);
        address wBtcOracle = _deployOracle(ORACLE_DECIMALS_BTC, ORACLE_CONVERSION_W_BTC);
        address stEthOracle = _deployOracle(ORACLE_DECIMALS_ETH, ORACLE_CONVERSION_ST_ETH);

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

        _deployVaults(tanssi);

        vm.startPrank(tanssi);
        address operatorRewardsAddress = deployRewards.deployOperatorRewardsContract(
            tanssi, address(networkMiddlewareService), OPERATOR_SHARE, owner
        );
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            address(vaultFactory), address(networkMiddlewareService), operatorRewardsAddress, tanssi
        );
        stakerRewardsFactory = ODefaultStakerRewardsFactory(stakerRewardsFactoryAddress);

        _deployMiddlewareWithProxy(operatorRewardsAddress, stakerRewardsFactoryAddress);
        middlewareReader = OBaseMiddlewareReader(address(middleware));

        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware));
        _deployGateway();

        middleware.setGateway(address(gateway));
        middleware.setCollateralToOracle(address(usdc), usdcOracle);
        middleware.setCollateralToOracle(address(wBTC), wBtcOracle);
        middleware.setCollateralToOracle(address(stETH), stEthOracle);
        vm.stopPrank();

        _registerOperatorAndOptIn(operator1, tanssi, address(vaultsData.v1.vault), false);
        _registerOperatorAndOptIn(operator1, tanssi, address(vaultsData.v2.vault), false);
        _registerOperatorAndOptIn(operator2, tanssi, address(vaultsData.v2.vault), true);
        _registerOperatorAndOptIn(operator3, tanssi, address(vaultsData.v2.vault), true);
        _registerOperatorAndOptIn(operator3, tanssi, address(vaultsData.v3.vault), false);
        _registerOperatorAndOptIn(operator4, tanssi, address(vaultsData.v3.vault), true);
        _registerOperatorAndOptIn(operator5, tanssi, address(vaultsData.v3.vault), true);
        _registerOperatorAndOptIn(operator5, tanssi, address(vaultsData.v4.vault), false);
        _registerOperatorAndOptIn(operator6, tanssi, address(vaultsData.v4.vault), true);
        _registerOperatorAndOptIn(operator7, tanssi, address(vaultsData.v5.vault), false);

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);
        _setLimitForNetworkAndOperators(tanssi);
        _depositToVaults();

        vm.stopPrank();
    }

    function _deployTokens() private {
        DeployCollateral deployCollateral = new DeployCollateral();
        address usdcAddress = deployCollateral.deployCollateral("usdc", TOKEN_DECIMALS_USDC);
        usdc = Token(usdcAddress);
        address wBTCAddress = deployCollateral.deployCollateral("wBTC", TOKEN_DECIMALS_BTC);
        wBTC = Token(wBTCAddress);
        address stETHAddress = deployCollateral.deployCollateral("stETH", TOKEN_DECIMALS_ETH);
        stETH = Token(stETHAddress);
        address starAddress = deployCollateral.deployCollateral("STAR", TOKEN_DECIMALS_USDC);
        STAR = Token(starAddress);
    }

    function _deployMiddlewareWithProxy(address operatorRewardsAddress, address stakerRewardsFactoryAddress) private {
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(operatorRegistry),
            vaultRegistry: address(vaultFactory),
            operatorNetworkOptIn: address(operatorNetworkOptInService),
            owner: owner,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: address(0)
        });
        DeployTanssiEcosystem deployTanssi = new DeployTanssiEcosystem();
        middleware = deployTanssi.deployMiddlewareWithProxy(params, operatorRewardsAddress, stakerRewardsFactoryAddress);

        networkMiddlewareService.setMiddleware(address(middleware));
    }

    function _deployVaults(
        address _owner
    ) private {
        address vault;
        address delegator;
        address slasher;

        // Operators 1 and 7 will use Specific Operator Vaults, so they need to be registered before deploying the vaults
        vm.startPrank(operator1);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        vm.startPrank(operator7);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);

        vm.startPrank(tanssi);
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.OPERATOR_SPECIFIC,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(usdc),
            owner: _owner,
            operator: operator1,
            network: address(0)
        });
        (vault, delegator,) = deployVault.createBaseVault(params);
        vaultsData.v1.vault = IVault(vault);
        vaultsData.v1.delegator = delegator;

        params.delegatorIndex = VaultManager.DelegatorType.FULL_RESTAKE;
        params.collateral = address(wBTC);
        params.operator = address(0);
        (vault, delegator,) = deployVault.createBaseVault(params);
        vaultsData.v2.vault = IVault(vault);
        vaultsData.v2.delegator = delegator;

        params.delegatorIndex = VaultManager.DelegatorType.NETWORK_RESTAKE;
        params.collateral = address(wBTC);
        (vault, delegator, slasher) = deployVault.createSlashableVault(params);
        vaultsData.v3.vault = IVault(vault);
        vaultsData.v3.delegator = delegator;
        vaultsData.v3.slasher = slasher;

        params.delegatorIndex = VaultManager.DelegatorType.NETWORK_RESTAKE;
        params.collateral = address(stETH);
        (vault, delegator, slasher) = deployVault.createVaultVetoed(params, VETO_DURATION);
        vaultsData.v4.vault = IVault(vault);
        vaultsData.v4.delegator = delegator;
        vaultsData.v4.slasher = slasher;

        params.delegatorIndex = VaultManager.DelegatorType.OPERATOR_NETWORK_SPECIFIC;
        params.collateral = address(stETH);
        params.operator = operator7;
        params.network = tanssi;
        (vault, delegator, slasher) = deployVault.createVaultVetoed(params, VETO_DURATION);
        vaultsData.v5.vault = IVault(vault);
        vaultsData.v5.delegator = delegator;
        vaultsData.v5.slasher = slasher;

        IVetoSlasher(vaultsData.v4.slasher).setResolver(0, resolver1, hex"");
        IVetoSlasher(vaultsData.v5.slasher).setResolver(0, resolver2, hex"");

        vm.stopPrank();
    }

    function _deployOracle(uint8 decimals, int256 answer) private returns (address) {
        MockV3Aggregator oracle = new MockV3Aggregator(decimals, answer);
        return address(oracle);
    }

    function _deployGateway() private returns (address) {
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

    function _registerEntitiesToMiddleware(
        address _owner
    ) private {
        vm.startPrank(_owner);
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });
        middleware.registerSharedVault(address(vaultsData.v1.vault), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultsData.v2.vault), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultsData.v3.vault), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultsData.v4.vault), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultsData.v5.vault), stakerRewardsParams);

        middleware.registerOperator(operator1, abi.encode(OPERATOR1_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        middleware.registerOperator(operator3, abi.encode(OPERATOR3_KEY), address(0));
        middleware.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
        middleware.registerOperator(operator5, abi.encode(OPERATOR5_KEY), address(0));
        middleware.registerOperator(operator6, abi.encode(OPERATOR6_KEY), address(0));
        middleware.registerOperator(operator7, abi.encode(OPERATOR7_KEY), address(0));
        vm.stopPrank();
    }

    function _registerOperatorAndOptIn(address _operator, address _network, address _vault, bool firstTime) private {
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
    ) private {
        vm.startPrank(_owner);
        INetworkRestakeDelegator(vaultsData.v3.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR3_SHARES_V3
        );
        INetworkRestakeDelegator(vaultsData.v3.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator4, OPERATOR4_SHARES_V3
        );
        INetworkRestakeDelegator(vaultsData.v3.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator5, OPERATOR5_SHARES_V3
        );

        INetworkRestakeDelegator(vaultsData.v4.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator5, OPERATOR5_SHARES_V4
        );
        INetworkRestakeDelegator(vaultsData.v4.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR6_SHARES_V4
        );
        vm.stopPrank();
    }

    function _setLimitForNetworkAndOperators(
        address _owner
    ) private {
        vm.startPrank(_owner);
        IOperatorSpecificDelegator(vaultsData.v1.delegator).setMaxNetworkLimit(0, VAULT1_NETWORK_LIMIT);
        IFullRestakeDelegator(vaultsData.v2.delegator).setMaxNetworkLimit(0, VAULT2_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsData.v3.delegator).setMaxNetworkLimit(0, VAULT3_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsData.v4.delegator).setMaxNetworkLimit(0, VAULT4_NETWORK_LIMIT);
        IOperatorSpecificDelegator(vaultsData.v5.delegator).setMaxNetworkLimit(0, VAULT5_NETWORK_LIMIT);

        IOperatorSpecificDelegator(vaultsData.v1.delegator).setNetworkLimit(tanssi.subnetwork(0), VAULT1_NETWORK_LIMIT);
        IFullRestakeDelegator(vaultsData.v2.delegator).setNetworkLimit(tanssi.subnetwork(0), VAULT2_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsData.v3.delegator).setNetworkLimit(tanssi.subnetwork(0), VAULT3_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsData.v4.delegator).setNetworkLimit(tanssi.subnetwork(0), VAULT4_NETWORK_LIMIT);

        // Only Vault2 is Full Restake
        IFullRestakeDelegator(vaultsData.v2.delegator).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator1, OPERATOR1_LIMIT_V2
        );
        IFullRestakeDelegator(vaultsData.v2.delegator).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, OPERATOR2_LIMIT_V2
        );
        IFullRestakeDelegator(vaultsData.v2.delegator).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, OPERATOR3_LIMIT_V2
        );
        vm.stopPrank();
    }

    function _depositToVaults() private {
        // Operator 1
        _depositToVault(vaultsData.v1.vault, operator1, OPERATOR1_STAKE_V1_USDC, usdc, true);
        _depositToVault(vaultsData.v2.vault, operator1, OPERATOR1_STAKE_V2_WBTC, wBTC, true);
        // Operator 2
        _depositToVault(vaultsData.v2.vault, operator2, OPERATOR2_STAKE_V2_WBTC, wBTC, true);
        // Operator 3
        _depositToVault(vaultsData.v2.vault, operator3, OPERATOR3_STAKE_V2_WBTC, wBTC, true);
        _depositToVault(vaultsData.v3.vault, operator3, OPERATOR3_STAKE_V3_WBTC, wBTC, true);
        // Operator 4
        _depositToVault(vaultsData.v3.vault, operator4, OPERATOR4_STAKE_V3_WBTC, wBTC, true);
        // Operator 5
        _depositToVault(vaultsData.v3.vault, operator5, OPERATOR5_STAKE_V3_WBTC, wBTC, true);
        _depositToVault(vaultsData.v4.vault, operator5, OPERATOR5_STAKE_V4_STETH, stETH, true);
        // Operator
        _depositToVault(vaultsData.v4.vault, operator6, OPERATOR6_STAKE_V4_STETH, stETH, true);
        // Operator
        _depositToVault(vaultsData.v5.vault, operator7, OPERATOR7_STAKE_V5_STETH, stETH, true);
    }

    function _depositToVault(
        IVault vault,
        address depositor,
        uint256 amount,
        Token collateral,
        bool mintFirst
    ) private {
        if (mintFirst) {
            collateral.mint(depositor, amount);
        }
        vm.startPrank(depositor);
        collateral.approve(address(vault), amount * 10);
        vault.deposit(depositor, amount);
        vm.stopPrank();
    }

    function _withdrawFromVault(IVault vault, address withdrawer, uint256 amount) private {
        vm.startPrank(withdrawer);
        vault.withdraw(withdrawer, amount);
        vm.stopPrank();
    }

    function _loadRewardsRootAndProof(
        uint48 eraIndex,
        uint48 operator
    )
        private
        view
        returns (uint48 epoch, bytes32 rewardsRoot, bytes32[] memory proof, uint32 points, uint32 totalPoints)
    {
        string memory project_root = vm.projectRoot();
        string memory path = string.concat(project_root, "/test/integration/rewards_data.json");
        string memory json = vm.readFile(path);

        string memory key = string.concat("$.", vm.toString(eraIndex), ".root");
        rewardsRoot = vm.parseJsonBytes32(json, key);

        key = string.concat("$.", vm.toString(eraIndex), ".epoch");
        epoch = uint48(vm.parseJsonUint(json, key));

        key = string.concat("$.", vm.toString(eraIndex), ".operator", vm.toString(operator), "_proof");
        proof = vm.parseJsonBytes32Array(json, key);

        key = string.concat("$.", vm.toString(eraIndex), ".operator", vm.toString(operator), "_points");
        points = uint32(vm.parseJsonUint(json, key));

        key = string.concat("$.", vm.toString(eraIndex), ".total_points");
        totalPoints = uint32(vm.parseJsonUint(json, key));
    }

    function _prepareRewardsDistribution(uint48 eraIndex, uint256 amountToDistribute) private returns (uint48) {
        (uint48 epoch, bytes32 rewardsRoot,,, uint32 totalPoints) = _loadRewardsRootAndProof(eraIndex, 1);

        uint48 epochStartTs = middleware.getEpochStart(epoch);
        vm.warp(epochStartTs + 1);

        STAR.mint(address(middleware), amountToDistribute);

        vm.startPrank(address(gateway));
        middleware.distributeRewards(epoch, eraIndex, totalPoints, amountToDistribute, rewardsRoot, address(STAR));
        vm.stopPrank();

        return epoch;
    }

    function _claimAndCheckOperatorRewardsForOperator(
        uint256 amountToDistribute,
        uint48 eraIndex,
        bytes32 operatorKey,
        address operator,
        uint48 operatorNumber,
        bool checkBalance
    ) private returns (uint256 expectedRewardsForStakers) {
        (,, bytes32[] memory proof, uint32 points, uint32 totalPoints) =
            _loadRewardsRootAndProof(eraIndex, operatorNumber);

        {
            bytes memory additionalData = abi.encode(ADMIN_FEE, new bytes(0), new bytes(0));

            IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards
                .ClaimRewardsInput({
                operatorKey: operatorKey,
                eraIndex: eraIndex,
                totalPointsClaimable: points,
                proof: proof,
                data: additionalData
            });

            operatorRewards.claimRewards(claimRewardsData);
        }

        expectedRewardsForStakers =
            _calculateAndCheckBalance(checkBalance, operator, amountToDistribute, points, totalPoints);
    }

    function _calculateAndCheckBalance(
        bool checkBalance,
        address operator,
        uint256 amountToDistribute,
        uint32 points,
        uint32 totalPoints
    ) private view returns (uint256 expectedRewardsForStakers) {
        if (checkBalance) {
            uint256 expectedRewardsForOperator =
                amountToDistribute.mulDiv(points, totalPoints).mulDiv(OPERATOR_SHARE, MAX_PERCENTAGE);
            expectedRewardsForStakers = amountToDistribute.mulDiv(points, totalPoints) - expectedRewardsForOperator;

            assertEq(STAR.balanceOf(operator), expectedRewardsForOperator);
        }
    }

    function _checkClaimableRewardsVault2(
        uint256 expectedRewardsStakerVault2,
        uint48 epoch
    ) private view returns (uint256 rewardsOperator1, uint256 rewardsOperator2, uint256 rewardsOperator3) {
        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));

        // Operator 1
        rewardsOperator1 = expectedRewardsStakerVault2.mulDiv(OPERATOR1_STAKE_V2_WBTC, VAULT2_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault2, epoch, operator1, rewardsOperator1);

        // Operator 2
        rewardsOperator2 = expectedRewardsStakerVault2.mulDiv(OPERATOR2_STAKE_V2_WBTC, VAULT2_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault2, epoch, operator2, rewardsOperator2);

        // Operator 3
        rewardsOperator3 = expectedRewardsStakerVault2.mulDiv(OPERATOR3_STAKE_V2_WBTC, VAULT2_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault2, epoch, operator3, rewardsOperator3);
    }

    function _checkClaimableRewardsVault3(uint256 expectedRewardsStakerVault3, uint48 epoch) private view {
        address stakerRewardsContractVault3 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v3.vault));

        // Operator 3
        uint256 expectedRewards = expectedRewardsStakerVault3.mulDiv(OPERATOR3_STAKE_V3_WBTC, VAULT3_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault3, epoch, operator3, expectedRewards);

        // Operator 4
        expectedRewards = expectedRewardsStakerVault3.mulDiv(OPERATOR4_STAKE_V3_WBTC, VAULT3_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault3, epoch, operator4, expectedRewards);

        // Operator 5
        expectedRewards = expectedRewardsStakerVault3.mulDiv(OPERATOR5_STAKE_V3_WBTC, VAULT3_TOTAL_STAKE);
        _checkClaimableRewards(stakerRewardsContractVault3, epoch, operator5, expectedRewards);
    }

    function _checkClaimableRewardsVault4(
        uint256 expectedRewardsStakerVault4,
        uint256 totalStakeVault4,
        uint48 epoch
    ) private view {
        address stakerRewardsContractVault4 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v4.vault));

        // Operator 5 in Vault 4
        uint256 expectedRewards = expectedRewardsStakerVault4.mulDiv(OPERATOR5_STAKE_V4_STETH, totalStakeVault4);
        _checkClaimableRewards(stakerRewardsContractVault4, epoch, operator5, expectedRewards);

        // Operator 6 in Vault 4
        expectedRewards = expectedRewardsStakerVault4.mulDiv(OPERATOR6_STAKE_V4_STETH, totalStakeVault4);
        _checkClaimableRewards(stakerRewardsContractVault4, epoch, operator6, expectedRewards);
    }

    function _checkClaimableRewards(
        address stakerRewards,
        uint48 epoch,
        address operator,
        uint256 expectedRewards
    ) private view {
        uint256 actualRewards = IODefaultStakerRewards(stakerRewards).claimable(epoch, operator, address(STAR));
        assertApproxEqAbs(expectedRewards, actualRewards, 1);
    }

    function _prepareOperatorsInMultipleVaults(address operatorA, address operatorB, uint256 numberOfVaults) private {
        uint256 NETWORK_LIMIT = 100 ether;

        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: ADMIN_FEE,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });

        for (uint256 i = 0; i < numberOfVaults; i++) {
            vm.startPrank(tanssi);
            DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
                epochDuration: VAULT_EPOCH_DURATION,
                depositWhitelist: false,
                depositLimit: 0,
                delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
                shouldBroadcast: false,
                vaultConfigurator: address(vaultConfigurator),
                collateral: address(wBTC),
                owner: owner,
                operator: address(0),
                network: address(0)
            });
            (address vault, address delegator,) = deployVault.createSlashableVault(params);

            middleware.registerSharedVault(address(vault), stakerRewardsParams);
            INetworkRestakeDelegator(delegator).setOperatorNetworkShares(tanssi.subnetwork(0), operatorA, 1);
            INetworkRestakeDelegator(delegator).setOperatorNetworkShares(tanssi.subnetwork(0), operatorB, 1);
            INetworkRestakeDelegator(delegator).setMaxNetworkLimit(0, NETWORK_LIMIT);
            INetworkRestakeDelegator(delegator).setNetworkLimit(tanssi.subnetwork(0), NETWORK_LIMIT);
            vm.stopPrank();

            _registerOperatorAndOptIn(operatorA, tanssi, vault, i == 0);
            _registerOperatorAndOptIn(operatorB, tanssi, vault, i == 0);

            _depositToVault(IVault(vault), operatorA, 1 ether, wBTC, true);
            _depositToVault(IVault(vault), operatorB, 1 ether, wBTC, true);
        }

        vm.startPrank(tanssi);
        middleware.registerOperator(operatorA, abi.encode(OPERATOR8_KEY), address(0));
        middleware.registerOperator(operatorB, abi.encode(OPERATOR9_KEY), address(0));
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        POWER
    // ************************************************************************************************

    function testOperatorPower() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        Middleware.ValidatorData[] memory validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());

        // On Vault 1: Operator 1 is the only staker.
        // On Vault 2: Operator 1 has 2 BTC Staked and it matches its limit.
        uint256 expectedOperatorPower1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC) // Normalized to 18 decimals
            + OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        assertEq(validators[0].power, expectedOperatorPower1);

        // OOn Vault 2: Operator 2 has just 1 BTC staked, but delegator is full restake and their limit is 2 BTC. Since vault has more than the limit, the operator stake taken into account is their limit.
        uint256 expectedOperatorPower2 =
            OPERATOR2_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        assertEq(validators[1].power, expectedOperatorPower2);

        // On Vault 2: Operator 3 has 3 BTC staked, but delegator is full restake and their limit is 2 BTC. So only 2 BTC are taken into account.
        // On Vault 3: delegator is network restake and OP3 is assigned 1/5 shares
        uint256 expectedOperatorPower3 = OPERATOR3_LIMIT_V2.mulDiv(
            uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
        )
            + VAULT3_TOTAL_STAKE.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC).mulDiv(
                OPERATOR3_SHARES_V3, VAULT3_TOTAL_SHARES
            );
        assertEq(validators[2].power, expectedOperatorPower3);

        // On Vault 3: delegator is network restake and OP4 is assigned 1/5 shares
        uint256 expectedOperatorPower4 = VAULT3_TOTAL_STAKE.mulDiv(
            uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
        ).mulDiv(OPERATOR4_SHARES_V3, VAULT3_TOTAL_SHARES);
        assertEq(validators[3].power, expectedOperatorPower4);

        // On Vault 3: delegator is network restake and OP5 is assigned 2/5 shares
        // On Vault 4: delegator is network restake and OP5 is assigned 2/3 shares
        uint256 expectedOperatorPower5 = VAULT3_TOTAL_STAKE.mulDiv(OPERATOR5_SHARES_V3, VAULT3_TOTAL_SHARES).mulDiv(
            uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
        )
            + VAULT4_TOTAL_STAKE.mulDiv(OPERATOR5_SHARES_V4, VAULT4_TOTAL_SHARES).mulDiv(
                uint256(ORACLE_CONVERSION_ST_ETH), 10 ** ORACLE_DECIMALS_ETH
            );
        assertEq(validators[4].power, expectedOperatorPower5);

        // On Vault 4: delegator is network restake and OP6 is assigned 1/3 shares
        uint256 expectedOperatorPower6 = VAULT4_TOTAL_STAKE.mulDiv(OPERATOR6_SHARES_V4, VAULT4_TOTAL_SHARES).mulDiv(
            uint256(ORACLE_CONVERSION_ST_ETH), 10 ** ORACLE_DECIMALS_ETH
        );
        assertEq(validators[5].power, expectedOperatorPower6);

        // On Vault 5: delegator is operator specific so all the stake is taken into account
        uint256 expectedOperatorPower7 =
            OPERATOR7_STAKE_V5_STETH.mulDiv(uint256(ORACLE_CONVERSION_ST_ETH), 10 ** ORACLE_DECIMALS_ETH);
        assertEq(validators[6].power, expectedOperatorPower7);
    }

    function testOperatorPowerWithAdditionalStake() public {
        address staker1 = makeAddr("staker1");
        address staker2 = makeAddr("staker2");

        uint256 staker1Stake = 20_000 * 10 ** TOKEN_DECIMALS_USDC;
        uint256 staker2Stake = 30_000 * 10 ** TOKEN_DECIMALS_USDC;

        _depositToVault(vaultsData.v1.vault, staker1, staker1Stake, usdc, true);
        _depositToVault(vaultsData.v1.vault, staker2, staker2Stake, usdc, true);

        vm.warp(NETWORK_EPOCH_DURATION + 2);
        Middleware.ValidatorData[] memory validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());

        // Vault 1 is Operator specific so all the power is taken into account for operator 1
        // Vault 2 is full restake so only the operator limit is taken into account
        uint256 expectedOperatorPower1 = (OPERATOR1_STAKE_V1_USDC + staker1Stake + staker2Stake).mulDiv(
            10 ** 18, 10 ** TOKEN_DECIMALS_USDC
        ) // Normalized to 18 decimals
            + OPERATOR1_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        assertEq(validators[0].power, expectedOperatorPower1);
    }

    function testOperatorPowerUpdatesAfterNetworkEpochOnDeposit() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        Middleware.ValidatorData[] memory validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());

        uint256 expectedOperatorPower1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC) // Normalized to 18 decimals
            + OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        assertEq(validators[0].power, expectedOperatorPower1);

        uint256 operator1_additional_stake = 100_000 * 10 ** TOKEN_DECIMALS_USDC;

        _depositToVault(vaultsData.v1.vault, operator1, operator1_additional_stake, usdc, true);

        // Power should not change until the network epoch ends
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);

        // Power should not change until the network epoch ends
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION / 2);
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);

        // Power changes even before the vault epoch ends, only network epoch needs to
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION);
        expectedOperatorPower1 += operator1_additional_stake.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC); // Normalized to 18 decimals
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);
    }

    function testOperatorPowerUpdatesAfterNetworkEpochOnWithdraw() public {
        vm.warp(NETWORK_EPOCH_DURATION + 2);
        Middleware.ValidatorData[] memory validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());

        uint256 expectedOperatorPower1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC) // Normalized to 18 decimals
            + OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        assertEq(validators[0].power, expectedOperatorPower1);

        uint256 operator1_withdraw_stake = 50_000 * 10 ** TOKEN_DECIMALS_USDC;

        _withdrawFromVault(vaultsData.v1.vault, operator1, operator1_withdraw_stake);

        // Power should not change until the network epoch ends
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);

        // Power should not change until the network epoch ends
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION / 2);
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);

        // Power changes even before the vault epoch ends, only network epoch needs to
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION);
        expectedOperatorPower1 -= operator1_withdraw_stake.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC); // Normalized to 18 decimals
        validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());
        assertEq(validators[0].power, expectedOperatorPower1);
    }

    // ************************************************************************************************
    // *                                       REWARDS DISTRIBUTION
    // ************************************************************************************************

    // We test each operator independently since rewards are accumulated in the stakers rewards contracts
    function testRewardsAreDistributedCorrectlyForOperator1() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR1_KEY, operator1, 1, true);

        // Operator 1 is active in vaults 1 and 2
        address stakerRewardsContractVault1 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v1.vault));
        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));

        uint256 operatorPowerVault1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC); // Normalized to 18 decimals
        uint256 operatorPowerVault2 =
            OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

        uint256 expectedRewardsStakerVault1 =
            expectedRewardsForStakers.mulDiv(operatorPowerVault1, operatorPowerVault1 + operatorPowerVault2);
        uint256 expectedRewardsStakerVault2 = expectedRewardsForStakers - expectedRewardsStakerVault1;

        assertEq(STAR.balanceOf(stakerRewardsContractVault1), expectedRewardsStakerVault1);
        assertEq(STAR.balanceOf(stakerRewardsContractVault2), expectedRewardsStakerVault2);

        // Vault 1
        {
            // Operator 1 is the only staker on the vault, so they get all the rewards minus the admin fee
            uint256 expectedRewardsStakerOperator1Vault1 =
                expectedRewardsStakerVault1.mulDiv(MAX_PERCENTAGE - ADMIN_FEE, MAX_PERCENTAGE);
            uint256 stakerRewardsOperator1Vault1 =
                IODefaultStakerRewards(stakerRewardsContractVault1).claimable(epoch, operator1, address(STAR));
            assertApproxEqAbs(expectedRewardsStakerOperator1Vault1, stakerRewardsOperator1Vault1, 1);
        }

        // Vault 2
        uint256 adminFeeStakerRewardsVault2 = expectedRewardsStakerVault2.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
        expectedRewardsStakerVault2 -= adminFeeStakerRewardsVault2;
        _checkClaimableRewardsVault2(expectedRewardsStakerVault2, epoch);
    }

    function testRewardsAreDistributedCorrectlyForOperator2() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR2_KEY, operator2, 2, true);

        // Operator 2 is only active on vault 2, so all the stakers rewards go to this vault
        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));
        uint256 expectedRewardsStakerVault2 = expectedRewardsForStakers;

        assertEq(STAR.balanceOf(stakerRewardsContractVault2), expectedRewardsStakerVault2);

        // Vault 2
        uint256 adminFeeStakerRewardsVault2 = expectedRewardsStakerVault2.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
        expectedRewardsStakerVault2 -= adminFeeStakerRewardsVault2;
        _checkClaimableRewardsVault2(expectedRewardsStakerVault2, epoch);
    }

    function testRewardsAreDistributedCorrectlyForOperator3() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR3_KEY, operator3, 3, true);

        // Operator 3 is active in vaults 2 and 3
        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));
        address stakerRewardsContractVault3 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v3.vault));

        // On Vault 2: Operator 3 has 3 BTC staked, but delegator is full restake and their limit is 2 BTC. So only 2 BTC are taken into account.
        // On Vault 3: delegator is network restake and OP3 is assigned 1/5 shares
        uint256 operatorPowerVault2 =
            OPERATOR3_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
        uint256 operatorPowerVault3 = VAULT3_TOTAL_STAKE.mulDiv(
            uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
        ).mulDiv(OPERATOR3_SHARES_V3, VAULT3_TOTAL_SHARES);

        uint256 expectedRewardsStakerVault2 =
            expectedRewardsForStakers.mulDiv(operatorPowerVault2, operatorPowerVault2 + operatorPowerVault3);
        uint256 expectedRewardsStakerVault3 = expectedRewardsForStakers - expectedRewardsStakerVault2;

        assertEq(STAR.balanceOf(stakerRewardsContractVault2), expectedRewardsStakerVault2);
        assertEq(STAR.balanceOf(stakerRewardsContractVault3), expectedRewardsStakerVault3);

        // Vault 2
        {
            uint256 adminFeeStakerRewardsVault2 = expectedRewardsStakerVault2.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault2 -= adminFeeStakerRewardsVault2;
            _checkClaimableRewardsVault2(expectedRewardsStakerVault2, epoch);
        }

        // Vault 3
        {
            uint256 adminFeeStakerRewardsVault3 = expectedRewardsStakerVault3.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault3 -= adminFeeStakerRewardsVault3;
            _checkClaimableRewardsVault3(expectedRewardsStakerVault3, epoch);
        }
    }

    function testRewardsAreDistributedCorrectlyForOperator4() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR4_KEY, operator4, 4, true);

        // Operator 4 is only active on vault 3, so all the stakers rewards go to this vault
        address stakerRewardsContractVault3 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v3.vault));
        uint256 expectedRewardsStakerVault3 = expectedRewardsForStakers;

        assertEq(STAR.balanceOf(stakerRewardsContractVault3), expectedRewardsStakerVault3);

        // Vault 3
        {
            uint256 adminFeeStakerRewardsVault3 = expectedRewardsStakerVault3.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault3 -= adminFeeStakerRewardsVault3;
            _checkClaimableRewardsVault3(expectedRewardsStakerVault3, epoch);
        }
    }

    function testRewardsAreDistributedCorrectlyForOperator5() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR5_KEY, operator5, 5, true);

        // Operator 5 is active in vaults 3 and 4
        address stakerRewardsContractVault3 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v3.vault));
        address stakerRewardsContractVault4 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v4.vault));

        // On Vault 3: delegator is network restake and OP5 is assigned 2/5 shares
        // On Vault 4: delegator is network restake and OP5 is assigned 2/3 shares
        uint256 operatorPowerVault3 = VAULT3_TOTAL_STAKE.mulDiv(OPERATOR5_SHARES_V3, VAULT3_TOTAL_SHARES).mulDiv(
            uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
        );
        uint256 operatorPowerVault4 = VAULT4_TOTAL_STAKE.mulDiv(OPERATOR5_SHARES_V4, VAULT4_TOTAL_SHARES).mulDiv(
            uint256(ORACLE_CONVERSION_ST_ETH), 10 ** ORACLE_DECIMALS_ETH
        );

        uint256 expectedRewardsStakerVault3 =
            expectedRewardsForStakers.mulDiv(operatorPowerVault3, operatorPowerVault3 + operatorPowerVault4);
        uint256 expectedRewardsStakerVault4 = expectedRewardsForStakers - expectedRewardsStakerVault3;

        assertEq(STAR.balanceOf(stakerRewardsContractVault3), expectedRewardsStakerVault3);
        assertEq(STAR.balanceOf(stakerRewardsContractVault4), expectedRewardsStakerVault4);

        // Vault 3
        {
            uint256 adminFeeStakerRewardsVault3 = expectedRewardsStakerVault3.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault3 -= adminFeeStakerRewardsVault3;
            _checkClaimableRewardsVault3(expectedRewardsStakerVault3, epoch);
        }

        // Vault 4
        {
            uint256 totalStakeVault4 = VAULT4_TOTAL_STAKE;
            uint256 adminFeeStakerRewardsVault4 = expectedRewardsStakerVault4.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault4 -= adminFeeStakerRewardsVault4;
            _checkClaimableRewardsVault4(expectedRewardsStakerVault4, totalStakeVault4, epoch);
        }
    }

    function testRewardsAreDistributedCorrectlyForOperator7() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR7_KEY, operator7, 7, true);

        // Operator 7 is only active on vault 5, so all the stakers rewards go to this vault
        address stakerRewardsContractVault5 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v5.vault));
        uint256 expectedRewardsStakerVault5 = expectedRewardsForStakers;

        assertEq(STAR.balanceOf(stakerRewardsContractVault5), expectedRewardsStakerVault5);

        // Vault 5
        {
            uint256 adminFeeStakerRewardsVault5 = expectedRewardsStakerVault5.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            expectedRewardsStakerVault5 -= adminFeeStakerRewardsVault5;

            // Operator 7 in Vault 5
            uint256 expectedRewards = expectedRewardsStakerVault5;
            _checkClaimableRewards(stakerRewardsContractVault5, epoch, operator7, expectedRewards);
        }
    }

    function testClaimingRewardsRevertsForOperator6() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        _prepareRewardsDistribution(eraIndex, amountToDistribute);

        // Operator 6 had no rewards on this epoch
        (,, bytes32[] memory proof, uint32 points,) = _loadRewardsRootAndProof(eraIndex, 6);
        assertEq(0, proof.length);

        bytes memory additionalData = abi.encode(ADMIN_FEE, new bytes(0), new bytes(0));
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: OPERATOR6_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: points,
            proof: proof,
            data: additionalData
        });

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__InvalidProof.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testRewardsAreDistributedCorrectlyForMultipleOperators() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        // This test will use vault 3, which has 3 active operators. Each of them will perform claim.
        uint256 expectedRewardsForStakersFromOperator1;
        uint256 expectedRewardsForStakersFromOperator2;
        uint256 expectedRewardsForStakersFromOperator3;

        // Operator 1
        {
            uint256 expectedRewardsForStakers = _claimAndCheckOperatorRewardsForOperator(
                amountToDistribute, eraIndex, OPERATOR1_KEY, operator1, 1, true
            );

            uint256 operatorPowerVault1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC); // Normalized to 18 decimals
            uint256 operatorPowerVault2 =
                OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

            uint256 expectedRewardsStakerVault1 =
                expectedRewardsForStakers.mulDiv(operatorPowerVault1, operatorPowerVault1 + operatorPowerVault2);
            expectedRewardsForStakersFromOperator1 = expectedRewardsForStakers - expectedRewardsStakerVault1;
        }

        // Operator 2
        {
            uint256 expectedRewardsForStakers = _claimAndCheckOperatorRewardsForOperator(
                amountToDistribute, eraIndex, OPERATOR2_KEY, operator2, 2, true
            );
            // Operator 2 is only active on vault 2, so all the stakers rewards go to this vault
            expectedRewardsForStakersFromOperator2 = expectedRewardsForStakers;
        }

        // Operator 3
        {
            uint256 expectedRewardsForStakers = _claimAndCheckOperatorRewardsForOperator(
                amountToDistribute, eraIndex, OPERATOR3_KEY, operator3, 3, true
            );
            // Operator 3 is active in vaults 2 and 3
            // On Vault 2: Operator 3 has 3 BTC staked, but delegator is full restake and their limit is 2 BTC. So only 2 BTC are taken into account.
            // On Vault 3: delegator is network restake and OP3 is assigned 1/5 shares
            uint256 operatorPowerVault2 =
                OPERATOR3_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);
            uint256 operatorPowerVault3 = VAULT3_TOTAL_STAKE.mulDiv(
                uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
            ).mulDiv(OPERATOR3_SHARES_V3, VAULT3_TOTAL_SHARES);

            expectedRewardsForStakersFromOperator3 =
                expectedRewardsForStakers.mulDiv(operatorPowerVault2, operatorPowerVault2 + operatorPowerVault3);
        }

        // Operator 2 is only active on vault 2, so all the stakers rewards go to this vault
        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));
        uint256 expectedRewardsStakerVault2 = expectedRewardsForStakersFromOperator1
            + expectedRewardsForStakersFromOperator2 + expectedRewardsForStakersFromOperator3;

        assertEq(STAR.balanceOf(stakerRewardsContractVault2), expectedRewardsStakerVault2);

        // Vault 2
        uint256 adminFeeStakerRewardsVault2 = expectedRewardsStakerVault2.mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
        expectedRewardsStakerVault2 -= adminFeeStakerRewardsVault2;

        // Check claimable rewards
        (uint256 rewardsOperator1, uint256 rewardsOperator2, uint256 rewardsOperator3) =
            _checkClaimableRewardsVault2(expectedRewardsStakerVault2, epoch);

        // Claim rewards and check balances
        {
            uint256 previousBalance = STAR.balanceOf(operator1);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator1, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator1), previousBalance + rewardsOperator1);
        }

        {
            uint256 previousBalance = STAR.balanceOf(operator2);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator2, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator2), previousBalance + rewardsOperator2);
        }

        {
            uint256 previousBalance = STAR.balanceOf(operator3);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator3, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator3), previousBalance + rewardsOperator3);
        }
    }

    function testDistributingAndClaimingRewardsForMultipleEpochs() public {
        uint256 amountToDistribute = 100 ether;
        // Distribute rewards for 2 epochs, with 2 eras per epoch
        _prepareRewardsDistribution(1, amountToDistribute);
        _prepareRewardsDistribution(2, amountToDistribute);
        _prepareRewardsDistribution(3, amountToDistribute);
        _prepareRewardsDistribution(4, amountToDistribute);

        // Claim rewards for operator 2 on era index 1, 2, and 4
        _claimAndCheckOperatorRewardsForOperator(amountToDistribute, 1, OPERATOR2_KEY, operator2, 2, false);
        _claimAndCheckOperatorRewardsForOperator(amountToDistribute, 2, OPERATOR2_KEY, operator2, 2, false);
        _claimAndCheckOperatorRewardsForOperator(amountToDistribute, 4, OPERATOR2_KEY, operator2, 2, false);

        // 20/100 points on era index 1, 60/100 points on era index 2
        uint256 rewardsOperator2Epoch1 = 20 ether + 60 ether;
        // 0/100 points on era index 3, 20/100 points on era index 4
        uint256 rewardsOperator2Epoch2 = 20 ether;

        {
            uint256 expectedRewardsForOperator =
                (rewardsOperator2Epoch1 + rewardsOperator2Epoch2).mulDiv(OPERATOR_SHARE, MAX_PERCENTAGE);
            assertEq(STAR.balanceOf(operator2), expectedRewardsForOperator);
        }

        address stakerRewardsContractVault2 = operatorRewards.vaultToStakerRewardsContract(address(vaultsData.v2.vault));

        // Epoch 1
        {
            uint48 epoch = 1;
            uint256 expectedRewardsForStakersEpoch1 = rewardsOperator2Epoch1.mulDiv(
                MAX_PERCENTAGE - OPERATOR_SHARE, MAX_PERCENTAGE
            ).mulDiv(MAX_PERCENTAGE - ADMIN_FEE, MAX_PERCENTAGE);
            (uint256 rewardsOperator1, uint256 rewardsOperator2, uint256 rewardsOperator3) =
                _checkClaimableRewardsVault2(expectedRewardsForStakersEpoch1, epoch);

            // Claim rewards as stakers and check balances. Only stakers are the first 3 operators
            // Operator 1
            uint256 previousBalance = STAR.balanceOf(operator1);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator1, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator1), previousBalance + rewardsOperator1);

            // Operator 2
            previousBalance = STAR.balanceOf(operator2);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator2, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator2), previousBalance + rewardsOperator2);

            // Operator 3
            previousBalance = STAR.balanceOf(operator3);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator3, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator3), previousBalance + rewardsOperator3);
        }

        // Epoch 2
        {
            uint48 epoch = 2;
            uint256 expectedRewardsForStakersEpoch2 = rewardsOperator2Epoch2.mulDiv(
                MAX_PERCENTAGE - OPERATOR_SHARE, MAX_PERCENTAGE
            ).mulDiv(MAX_PERCENTAGE - ADMIN_FEE, MAX_PERCENTAGE);
            (uint256 rewardsOperator1, uint256 rewardsOperator2, uint256 rewardsOperator3) =
                _checkClaimableRewardsVault2(expectedRewardsForStakersEpoch2, epoch);

            // Claim rewards as stakers and check balances. Only stakers are the first 3 operators
            // Operator 1
            uint256 previousBalance = STAR.balanceOf(operator1);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator1, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator1), previousBalance + rewardsOperator1);

            // Operator 2
            previousBalance = STAR.balanceOf(operator2);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator2, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator2), previousBalance + rewardsOperator2);

            // Operator 3
            previousBalance = STAR.balanceOf(operator3);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimRewards(
                operator3, epoch, address(STAR), new bytes(0)
            );
            assertEq(STAR.balanceOf(operator3), previousBalance + rewardsOperator3);
        }

        // Admin Fee
        {
            vm.startPrank(tanssi);
            address recipient = makeAddr("recipient");

            uint256 expectedAdminFee = rewardsOperator2Epoch1.mulDiv(MAX_PERCENTAGE - OPERATOR_SHARE, MAX_PERCENTAGE)
                .mulDiv(ADMIN_FEE, MAX_PERCENTAGE);
            IODefaultStakerRewards(stakerRewardsContractVault2).claimAdminFee(recipient, 1, address(STAR));
            assertEq(STAR.balanceOf(recipient), expectedAdminFee);

            expectedAdminFee += rewardsOperator2Epoch2.mulDiv(MAX_PERCENTAGE - OPERATOR_SHARE, MAX_PERCENTAGE).mulDiv(
                ADMIN_FEE, MAX_PERCENTAGE
            );
            IODefaultStakerRewards(stakerRewardsContractVault2).claimAdminFee(recipient, 2, address(STAR));
            assertEq(STAR.balanceOf(recipient), expectedAdminFee);

            vm.stopPrank();
        }

        // Staker rewards contract should have distributed all the balance
        assertEq(STAR.balanceOf(stakerRewardsContractVault2), 0);
    }

    function testCannotReclaimRewardsIfEvmKeyChangesForOperator() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR2_KEY, operator2, 2, true);

        address operator2New = makeAddr("operator2New");

        // First we try directly updating directly, but it is not possible. This method is used to assign a new key to an existing evm operator, not the other way around.
        vm.startPrank(owner);
        vm.expectRevert(KeyManagerAddress.DuplicateKey.selector);
        middleware.updateOperatorKey(operator2New, abi.encode(OPERATOR2_KEY));

        // Then we try unregistering and registering again
        middleware.pauseOperator(operator2);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator2);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);

        vm.startPrank(operator2);
        // operatorRegistry.unregisterOperator(); // No such a thing. Only registering is possible.
        operatorNetworkOptInService.optOut(tanssi);
        operatorVaultOptInService.optOut(address(vaultsData.v2.vault));
        vm.stopPrank();

        vm.startPrank(operator2New);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(address(vaultsData.v2.vault));
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        vm.startPrank(owner);
        vm.expectRevert(KeyManagerAddress.DuplicateKey.selector);
        // registerOperator tries to call update key just like updateOperatorKey, but it already exists so it reverts
        middleware.registerOperator(operator2New, abi.encode(OPERATOR2_KEY), address(0));
        vm.stopPrank();

        // The substrate key still points to initial evm address
        address operatorFromKey = IOBaseMiddlewareReader(address(middleware)).operatorByKey(abi.encode(OPERATOR2_KEY));
        assertEq(operatorFromKey, operator2);

        // The initial EVM address points to no key, link in this direction is removed when unregistering
        bytes memory keyFromOperator = IOBaseMiddlewareReader(address(middleware)).operatorKey(operator2);
        assertEq(keyFromOperator, abi.encode(0));

        // The new EVM address points to no key since registration could not be completed.
        keyFromOperator = IOBaseMiddlewareReader(address(middleware)).operatorKey(operator2New);
        assertEq(keyFromOperator, abi.encode(0));

        // Try to claim anyway, it will revert with already claimed
        (,, bytes32[] memory proof, uint32 points, uint32 totalPoints) = _loadRewardsRootAndProof(eraIndex, 2);
        bytes memory additionalData = abi.encode(ADMIN_FEE, new bytes(0), new bytes(0));
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: OPERATOR2_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: points,
            proof: proof,
            data: additionalData
        });

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__AlreadyClaimed.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    function testOperatorCanClaimRewardsEvenAfterUnregistering() public {
        uint48 eraIndex = 1;
        uint256 amountToDistribute = 100 ether;
        uint48 epoch = _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 expectedRewardsForStakers =
            _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR2_KEY, operator2, 2, true);

        // Owner pauses and unregisters operator
        vm.startPrank(owner);
        middleware.pauseOperator(operator2);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        middleware.unregisterOperator(operator2);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);

        // Operator opts out
        vm.startPrank(operator2);
        // operatorRegistry.unregisterOperator(); // No such a thing. Only registering is possible.
        operatorNetworkOptInService.optOut(tanssi);
        operatorVaultOptInService.optOut(address(vaultsData.v2.vault));
        vm.stopPrank();

        // Try to claim, since substrate key still points to the original EVM address, claim is valid.
        (,, bytes32[] memory proof, uint32 points, uint32 totalPoints) = _loadRewardsRootAndProof(eraIndex, 2);
        bytes memory additionalData = abi.encode(ADMIN_FEE, new bytes(0), new bytes(0));
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: OPERATOR2_KEY,
            eraIndex: eraIndex,
            totalPointsClaimable: points,
            proof: proof,
            data: additionalData
        });

        vm.expectRevert(IODefaultOperatorRewards.ODefaultOperatorRewards__AlreadyClaimed.selector);
        operatorRewards.claimRewards(claimRewardsData);
    }

    // ************************************************************************************************
    // *                                       Slashing
    // ************************************************************************************************

    function testInstantSlashingOperator3() public {
        // Operator 3 has stake in vault2 (no slasher) and vault3 (instant slasher)
        vm.warp(VAULT_EPOCH_DURATION + 2);
        uint48 slashingEpoch = middleware.getCurrentEpoch();
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        vm.startPrank(gateway);
        middleware.slash(slashingEpoch, OPERATOR3_KEY, SLASHING_FRACTION);
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators = middlewareReader.getValidatorSet(middleware.getCurrentEpoch());

        // ---------------------
        // Operator 1
        {
            uint256 operator1PowerVault1 = OPERATOR1_STAKE_V1_USDC.mulDiv(10 ** 18, 10 ** TOKEN_DECIMALS_USDC); // Normalized to 18 decimals
            uint256 operator1PowerVault2 =
                OPERATOR1_STAKE_V2_WBTC.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

            // Operator 1 is slashed on vault 2 only, but it is not slashable so power stays the same.
            assertEq(validators[0].power, operator1PowerVault1 + operator1PowerVault2);
        }

        // Operator 2
        {
            // On Vault 2: Operator 2 has just 1 BTC staked, but delegator is full restake and their limit is 2 BTC. Since vault has more than the limit, the operator stake taken into account is their limit.
            // Operator 3 is slashed on vault 2, but it is not slashable so power stays the same.
            uint256 operator2PowerVault2 =
                OPERATOR2_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

            assertEq(validators[1].power, operator2PowerVault2);
        }

        uint256 operator3Vault3SlashedStake = OPERATOR3_STAKE_V3_WBTC.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);
        operator3Vault3SlashedStake.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

        // Operator 3
        {
            // On Vault 2: Operator 3 has 3 BTC staked, but delegator is full restake and their limit is 2 BTC. So only 2 BTC are taken into account. Vault is not slashable so power stays the same.

            uint256 operator3PowerVault2 =
                OPERATOR3_LIMIT_V2.mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

            // On Vault 3: delegator is network restake and OP3 is assigned 1/5 shares. Vault is slashable so power stays are reduced.
            uint256 operator3PowerVault3 = (VAULT3_TOTAL_STAKE - operator3Vault3SlashedStake).mulDiv(
                uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
            ).mulDiv(OPERATOR3_SHARES_V3, VAULT3_TOTAL_SHARES);

            assertEq(validators[2].power, operator3PowerVault2 + operator3PowerVault3);
        }

        // Operator 4
        {
            // On Vault 3: delegator is network restake and OP4 is assigned 1/5 shares
            // Operator 3 is slashed on vault 3, so total power for operator 4 is reduced on the vault
            uint256 operator4PowerVault3 = (VAULT3_TOTAL_STAKE - operator3Vault3SlashedStake).mulDiv(
                uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC
            ).mulDiv(OPERATOR4_SHARES_V3, VAULT3_TOTAL_SHARES);

            assertEq(validators[3].power, operator4PowerVault3);
        }

        // Operator 5
        {
            // On Vault 3: delegator is network restake and OP5 is assigned 2/5 shares
            // Operator 3 is slashed on vault 3, so total power for operator 5 is reduced on the vault
            uint256 operator5PowerVault3 = (VAULT3_TOTAL_STAKE - operator3Vault3SlashedStake).mulDiv(
                OPERATOR5_SHARES_V3, VAULT3_TOTAL_SHARES
            ).mulDiv(uint256(ORACLE_CONVERSION_W_BTC), 10 ** ORACLE_DECIMALS_BTC);

            // On Vault 4: delegator is network restake and OP5 is assigned 2/3 shares. Operator is not active on vault 4 so power stays the same.
            uint256 operator5PowerVault4 = VAULT4_TOTAL_STAKE.mulDiv(OPERATOR5_SHARES_V4, VAULT4_TOTAL_SHARES).mulDiv(
                uint256(ORACLE_CONVERSION_ST_ETH), 10 ** ORACLE_DECIMALS_ETH
            );

            assertEq(validators[4].power, operator5PowerVault4 + operator5PowerVault3);
        }
    }

    // ************************************************************************************************
    // *                                       GAS LIMITS
    // ************************************************************************************************

    function testDistributeRewardsWithOperatorInMultipleVaults() public {
        // Distribute rewards
        address operator8 = makeAddr("operator8");
        address operator9 = makeAddr("operator9");
        uint256 numberOfVaults = 100;

        _prepareOperatorsInMultipleVaults(operator8, operator9, numberOfVaults);

        // Distribute rewards
        uint48 eraIndex = 5;
        uint256 amountToDistribute = 100 ether;
        vm.warp(block.timestamp + 5 * NETWORK_EPOCH_DURATION);

        _prepareRewardsDistribution(eraIndex, amountToDistribute);

        uint256 initGas = gasleft();
        _claimAndCheckOperatorRewardsForOperator(amountToDistribute, eraIndex, OPERATOR8_KEY, operator8, 8, true);
        uint256 endGas = gasleft();

        // 30M is the tx gas limit in most of the networks. Gas usage 2025-04-24: 22895689
        assertLt(initGas - endGas, 30_000_000);
    }

    function testSlashOperatorInMultipleVaults() public {
        // Distribute rewards
        address operator8 = makeAddr("operator8");
        address operator9 = makeAddr("operator9");
        uint256 numberOfVaults = 100;

        _prepareOperatorsInMultipleVaults(operator8, operator9, numberOfVaults);

        // Distribute rewards
        vm.warp(VAULT_EPOCH_DURATION + 1);

        uint48 slashingEpoch = middleware.getCurrentEpoch();
        vm.startPrank(gateway);
        uint256 initGas = gasleft();
        middleware.slash(slashingEpoch, OPERATOR8_KEY, SLASHING_FRACTION);
        vm.stopPrank();

        uint256 endGas = gasleft();

        // 30M is the tx gas limit in most of the networks. Gas usage 2025-04-24: 27896693
        assertLt(initGas - endGas, 30_000_000);
    }
}
