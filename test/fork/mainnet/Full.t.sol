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
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IDefaultCollateral} from "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateral.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {RegisterForeignTokenParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {
    OperatingMode, ParaID, Command, InboundMessage
} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Types.sol";
import {MockGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockGateway.sol";
import {GatewayProxy} from "@tanssi-bridge-relayer/snowbridge/contracts/src/GatewayProxy.sol";
import {Verification} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Verification.sol";
import {AgentExecutor} from "@tanssi-bridge-relayer/snowbridge/contracts/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {IGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IGateway.sol";
import {Gateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Gateway.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {MiddlewareV2} from "test/unit/utils/MiddlewareV2.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract FullTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 2 days;
    uint48 public constant VETO_DURATION = 1 days;
    uint256 public constant SLASH_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_STAKE = 90 ether;
    uint256 public constant DEFAULT_WITHDRAW_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant OPERATOR2_KEY = bytes32(uint256(2));
    bytes32 public constant OPERATOR3_KEY = bytes32(uint256(3));
    bytes32 public constant OPERATOR4_KEY = bytes32(uint256(4));
    bytes32 public constant OPERATOR5_KEY = bytes32(uint256(5));
    bytes32 public constant OPERATOR6_KEY = bytes32(uint256(6));
    bytes32 public constant OPERATOR7_KEY = bytes32(uint256(7));
    bytes32 public constant OPERATOR8_KEY = bytes32(uint256(8));
    bytes32 public constant OPERATOR9_KEY = bytes32(uint256(9));
    bytes32 public constant OPERATOR10_KEY = bytes32(uint256(10));
    uint256 public constant OPERATOR_SHARE = 1;
    uint256 public constant TOTAL_SHARES_MEV_RESTAKED = 3;
    uint256 public constant TOTAL_SHARES_MEV_CAPITAL = 4;
    uint256 public constant TOTAL_SHARES_HASH_KEY_CLOUD = 2;
    uint256 public constant TOTAL_SHARES_RENZO_RESTAKED = 2;
    uint256 public constant TOTAL_SHARES_RE7_LABS = 1;
    uint256 public constant TOTAL_SHARES_RE7_LABS_RESTAKING = 3;
    uint256 public constant TOTAL_SHARES_CP0X_LRT = 3;
    uint256 public constant TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH = 4;
    uint256 public constant TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH = 3;
    uint256 public constant TOTAL_SHARES_GAUNTLET_RESTAKED_RETH = 6;
    uint256 public constant TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH = 6;

    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 500 ether;
    uint256 public constant TOTAL_NETWORK_SHARES = 2;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 10; // 10%
    uint8 public constant ORACLE_DECIMALS = 2;
    int256 public constant ORACLE_CONVERSION_TOKEN = 2000;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);
    address tanssi = owner;

    address public operator = makeAddr("operator");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public operator4 = makeAddr("operator4");
    address public operator5 = makeAddr("operator5");
    address public operator6 = makeAddr("operator6");
    address public operator7 = makeAddr("operator7");
    address public operator8 = makeAddr("operator8");
    address public operator9 = makeAddr("operator9");
    address public operator10 = makeAddr("operator10");

    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");

    address public relayer = makeAddr("relayer");

    address public oracle = makeAddr("oracle");
    address public forwarder = makeAddr("forwarder");

    MockGateway public gatewayLogic;
    GatewayProxy public gateway;

    // remote fees in DOT
    uint128 public outboundFee = 1e10;
    uint128 public registerTokenFee = 0;
    uint128 public sendTokenFee = 1e10;
    uint128 public createTokenFee = 1e10;
    uint128 public maxDestinationFee = 1e11;

    ParaID public bridgeHubParaID = ParaID.wrap(1013);
    bytes32 public bridgeHubAgentID = 0x03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314;
    address public bridgeHubAgent;

    ParaID public assetHubParaID = ParaID.wrap(1000);
    bytes32 public assetHubAgentID = 0x81c5ab2571199e3188135178f3c2c8e2d268be1313d029b30f534fa579b69b79;
    address public assetHubAgent;
    uint64 public maxDispatchGas = 500_000;
    uint256 public maxRefund = 1 ether;
    uint256 public reward = 1 ether;
    bytes32 public messageID = keccak256("cabbage");

    // For DOT
    uint8 public foreignTokenDecimals = 10;

    // ETH/DOT exchange rate
    UD60x18 public exchangeRate = ud60x18(0.0025e18);
    UD60x18 public multiplier = ud60x18(1e18);

    HelperConfig helperConfig;

    struct VaultStakeBeforeDeposit {
        uint256 mevRestakedStakeBeforeDeposit;
        uint256 mevCapitalStakeBeforeDeposit;
        uint256 hashKeyCloudStakeBeforeDeposit;
        uint256 renzoRestakedStakeBeforeDeposit;
        uint256 re7LabsStakeBeforeDeposit;
        uint256 re7LabsRestakingStakeBeforeDeposit;
        uint256 cp0xLrtStakeBeforeDeposit;
        uint256 gauntletRestakedWstStakeBeforeDeposit;
        uint256 gauntletRestakedCbStakeBeforeDeposit;
        uint256 gauntletRestakedSwStakeBeforeDeposit;
        uint256 gauntletRestakedRETHStakeBeforeDeposit;
        uint256 gauntletRestakedWBETHStakeBeforeDeposit;
    }

    struct VaultTotalStake {
        uint256 totalMevRestakedETHPower;
        uint256 totalMevCapitalETHPower;
        uint256 totalHashKeyCloudETHPower;
        uint256 totalRenzoRestakedETHPower;
        uint256 totalRe7LabsETHPower;
        uint256 totalre7LabsRestakingETHPower;
        uint256 totalCp0xLrtETHPower;
        uint256 totalGauntletRestakedWstETHPower;
        uint256 totalGauntletRestakedSwETHPower;
        uint256 totalGauntletRestakedRETHPower;
        uint256 totalGauntletRestakedWBETHPower;
    }

    struct EcosystemEntity {
        Middleware middleware;
        IDefaultCollateral wstETH;
        IDefaultCollateral rETH;
        IDefaultCollateral swETH;
        IDefaultCollateral wBETH;
    }

    HelperConfig.VaultsConfig public vaultsAddressesDeployed;
    EcosystemEntity public ecosystemEntities;
    VaultTotalStake public vaultTotalStake;
    VaultStakeBeforeDeposit public vaultStakeBeforeDeposit;

    function setUp() public {
        _deployBaseInfrastructure();
        _setLimitsAndShares(tanssi);
        _setupOperators();

        _registerEntitiesToMiddleware(owner);
        _setupGateway();
        _saveStakeBeforeDepositing();

        vm.startPrank(tanssi);
        ecosystemEntities.middleware.setCollateralToOracle(address(ecosystemEntities.wstETH), oracle);
        ecosystemEntities.middleware.setCollateralToOracle(address(ecosystemEntities.rETH), oracle);
        ecosystemEntities.middleware.setCollateralToOracle(address(ecosystemEntities.swETH), oracle);
        ecosystemEntities.middleware.setCollateralToOracle(address(ecosystemEntities.wBETH), oracle);
        vm.stopPrank();

        _handleDeposits();
    }

    function _deployBaseInfrastructure() private {
        // Check if it's good for mainnet
        vm.allowCheatcodes(address(0x6B5CF024365D5d5d0786673780CA7E3F07f85B63));
        DeployTanssiEcosystem deployTanssi = new DeployTanssiEcosystem();
        helperConfig = new HelperConfig();
        deployTanssi.deployTanssiEcosystem(helperConfig);
        address stETHCollateralAddress;
        address rETHCollateralAddress;
        address swETHCollateralAddress;
        address wBETHCollateralAddress;
        (
            ecosystemEntities.middleware,
            ,
            stETHCollateralAddress,
            rETHCollateralAddress,
            swETHCollateralAddress,
            wBETHCollateralAddress
        ) = deployTanssi.ecosystemEntities();
        ecosystemEntities.wstETH = IDefaultCollateral(stETHCollateralAddress);
        ecosystemEntities.rETH = IDefaultCollateral(rETHCollateralAddress);
        ecosystemEntities.swETH = IDefaultCollateral(swETHCollateralAddress);
        ecosystemEntities.wBETH = IDefaultCollateral(wBETHCollateralAddress);

        vaultsAddressesDeployed = helperConfig.getActiveVaultsConfig();
    }

    function _setupOperators() private {
        // ******************
        //    OPERATOR 1
        // ******************
        deal(address(ecosystemEntities.wstETH), operator, OPERATOR_INITIAL_BALANCE * 4);
        _registerOperator(
            operator, tanssi, vaultsAddressesDeployed.mevRestakedETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator, tanssi, vaultsAddressesDeployed.mevCapitalETH.vault, address(0));
        _registerOperator(
            operator, tanssi, vaultsAddressesDeployed.hashKeyCloudETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );

        // ******************
        //    OPERATOR 2
        // ******************
        deal(address(ecosystemEntities.wstETH), operator2, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.rETH), operator2, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.wBETH), operator2, OPERATOR_INITIAL_BALANCE);
        _registerOperator(operator2, tanssi, vaultsAddressesDeployed.mevCapitalETH.vault, address(0));
        _registerOperator(operator2, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));
        _registerOperator(operator2, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));

        // ******************
        //    OPERATOR 3
        // ******************
        deal(address(ecosystemEntities.wstETH), operator3, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.rETH), operator3, OPERATOR_INITIAL_BALANCE);
        _registerOperator(
            operator3,
            tanssi,
            vaultsAddressesDeployed.re7LabsRestakingETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator3, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));

        // ******************
        //    OPERATOR 4
        // ******************
        deal(address(ecosystemEntities.swETH), operator4, OPERATOR_INITIAL_BALANCE);
        _registerOperator(operator4, tanssi, vaultsAddressesDeployed.gauntletRestakedSwETH.vault, address(0));

        // ******************
        //    OPERATOR 5
        // ******************
        deal(address(ecosystemEntities.wBETH), operator5, OPERATOR_INITIAL_BALANCE);
        _registerOperator(operator5, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));

        // ******************
        //    OPERATOR 6
        // ******************
        deal(address(ecosystemEntities.wstETH), operator6, OPERATOR_INITIAL_BALANCE * 4);
        deal(address(ecosystemEntities.rETH), operator6, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.wBETH), operator6, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.swETH), operator6, OPERATOR_INITIAL_BALANCE);
        _registerOperator(
            operator6, tanssi, vaultsAddressesDeployed.mevRestakedETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator6, tanssi, vaultsAddressesDeployed.mevCapitalETH.vault, address(0));
        _registerOperator(
            operator6, tanssi, vaultsAddressesDeployed.cp0xLrtETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator6, tanssi, vaultsAddressesDeployed.gauntletRestakedWstETH.vault, address(0));
        _registerOperator(operator6, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));
        _registerOperator(operator6, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));
        _registerOperator(operator6, tanssi, vaultsAddressesDeployed.gauntletRestakedSwETH.vault, address(0));

        // ******************
        //    OPERATOR 7
        // ******************
        deal(address(ecosystemEntities.wstETH), operator7, OPERATOR_INITIAL_BALANCE * 2);
        deal(address(ecosystemEntities.rETH), operator7, OPERATOR_INITIAL_BALANCE);
        _registerOperator(
            operator7,
            tanssi,
            vaultsAddressesDeployed.renzoRestakedETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(
            operator7,
            tanssi,
            vaultsAddressesDeployed.re7LabsRestakingETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator7, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));

        // ******************
        //    OPERATOR 8
        // ******************
        deal(address(ecosystemEntities.wBETH), operator8, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.wstETH), operator8, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.swETH), operator8, OPERATOR_INITIAL_BALANCE);
        _registerOperator(operator8, tanssi, vaultsAddressesDeployed.gauntletRestakedWstETH.vault, address(0));
        _registerOperator(operator8, tanssi, vaultsAddressesDeployed.gauntletRestakedSwETH.vault, address(0));
        _registerOperator(operator8, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));

        // ******************
        //    OPERATOR 9
        // ******************
        deal(address(ecosystemEntities.wstETH), operator9, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.rETH), operator9, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.wBETH), operator9, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.swETH), operator9, OPERATOR_INITIAL_BALANCE);
        _registerOperator(
            operator9, tanssi, vaultsAddressesDeployed.cp0xLrtETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator9, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));
        _registerOperator(operator9, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));
        _registerOperator(operator9, tanssi, vaultsAddressesDeployed.gauntletRestakedSwETH.vault, address(0));

        // ******************
        //    OPERATOR 10
        // ******************
        deal(address(ecosystemEntities.wstETH), operator10, OPERATOR_INITIAL_BALANCE * 8);
        deal(address(ecosystemEntities.rETH), operator10, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.wBETH), operator10, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.swETH), operator10, OPERATOR_INITIAL_BALANCE);
        _registerOperator(
            operator10, tanssi, vaultsAddressesDeployed.mevRestakedETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator10, tanssi, vaultsAddressesDeployed.mevCapitalETH.vault, address(0));
        _registerOperator(
            operator10,
            tanssi,
            vaultsAddressesDeployed.hashKeyCloudETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(
            operator10, tanssi, vaultsAddressesDeployed.cp0xLrtETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator10, tanssi, vaultsAddressesDeployed.gauntletRestakedWstETH.vault, address(0));
        _registerOperator(
            operator10,
            tanssi,
            vaultsAddressesDeployed.re7LabsRestakingETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(
            operator10, tanssi, vaultsAddressesDeployed.re7LabsETH.vault, 0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(
            operator10,
            tanssi,
            vaultsAddressesDeployed.renzoRestakedETH.vault,
            0x9437B2a8cF3b69D782a61f9814baAbc172f72003
        );
        _registerOperator(operator10, tanssi, vaultsAddressesDeployed.gauntletRestakedRETH.vault, address(0));
        _registerOperator(operator10, tanssi, vaultsAddressesDeployed.gauntletRestakedWBETH.vault, address(0));
        _registerOperator(operator10, tanssi, vaultsAddressesDeployed.gauntletRestakedSwETH.vault, address(0));
    }

    function _handleDeposits() private {
        (,,,,, address operatorVaultOptInServiceAddress,,,) = helperConfig.activeNetworkConfig();

        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);

        vm.startPrank(operator);
        _depositToVault(
            IVault(vaultsAddressesDeployed.mevRestakedETH.vault), operator, OPERATOR_STAKE, ecosystemEntities.wstETH
        );
        _depositToVault(
            IVault(vaultsAddressesDeployed.mevCapitalETH.vault), operator, OPERATOR_STAKE, ecosystemEntities.wstETH
        );
        _depositToVault(
            IVault(vaultsAddressesDeployed.hashKeyCloudETH.vault), operator, OPERATOR_STAKE, ecosystemEntities.wstETH
        );
        vm.stopPrank();

        {
            // Scoped to help with stack depth
            vm.startPrank(operator2);

            _depositToVault(
                IVault(vaultsAddressesDeployed.mevCapitalETH.vault), operator2, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator2,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator2,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            vm.stopPrank();
        }

        {
            // Scoped to help with stack depth
            vm.startPrank(operator3);
            _depositToVault(
                IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault),
                operator3,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator3,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator4);
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault),
                operator4,
                OPERATOR_STAKE,
                ecosystemEntities.swETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator5);
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator5,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator6);
            _depositToVault(
                IVault(vaultsAddressesDeployed.mevRestakedETH.vault),
                operator6,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.mevCapitalETH.vault), operator6, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.cp0xLrtETH.vault), operator6, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWstETH.vault),
                operator6,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator6,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator6,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault),
                operator6,
                OPERATOR_STAKE,
                ecosystemEntities.swETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator7);
            _depositToVault(
                IVault(vaultsAddressesDeployed.renzoRestakedETH.vault),
                operator7,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault),
                operator7,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator7,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator8);
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWstETH.vault),
                operator8,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault),
                operator8,
                OPERATOR_STAKE,
                ecosystemEntities.swETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator8,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator9);
            _depositToVault(
                IVault(vaultsAddressesDeployed.cp0xLrtETH.vault), operator9, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator9,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator9,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault),
                operator9,
                OPERATOR_STAKE,
                ecosystemEntities.swETH
            );
            vm.stopPrank();
        }
        {
            // Scoped to help with stack depth
            vm.startPrank(operator10);
            _depositToVault(
                IVault(vaultsAddressesDeployed.mevRestakedETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.mevCapitalETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.hashKeyCloudETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.cp0xLrtETH.vault), operator10, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWstETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.re7LabsETH.vault), operator10, OPERATOR_STAKE, ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.renzoRestakedETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wstETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.rETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.wBETH
            );
            _depositToVault(
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault),
                operator10,
                OPERATOR_STAKE,
                ecosystemEntities.swETH
            );
            vm.stopPrank();
        }
        {
            vaultTotalStake.totalMevRestakedETHPower = (
                IVault(vaultsAddressesDeployed.mevRestakedETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalMevCapitalETHPower = (
                IVault(vaultsAddressesDeployed.mevCapitalETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalHashKeyCloudETHPower = (
                IVault(vaultsAddressesDeployed.hashKeyCloudETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalRenzoRestakedETHPower = (
                IVault(vaultsAddressesDeployed.renzoRestakedETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalRe7LabsETHPower = (
                IVault(vaultsAddressesDeployed.re7LabsETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalCp0xLrtETHPower = (
                IVault(vaultsAddressesDeployed.cp0xLrtETH.vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalGauntletRestakedWstETHPower = (
                IVault(vaultsAddressesDeployed.gauntletRestakedWstETH.vault).activeStake()
                    * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalre7LabsRestakingETHPower = (
                IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault).activeStake()
                    * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalGauntletRestakedSwETHPower = (
                IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault).activeStake()
                    * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalGauntletRestakedRETHPower = (
                IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault).activeStake()
                    * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;

            vaultTotalStake.totalGauntletRestakedWBETHPower = (
                IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault).activeStake()
                    * uint256(ORACLE_CONVERSION_TOKEN)
            ) / 10 ** ORACLE_DECIMALS;
        }
    }

    function _depositToVault(IVault _vault, address _operator, uint256 _amount, IERC20 collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: _owner,
            adminFeeClaimRoleHolder: _owner,
            adminFeeSetRoleHolder: _owner
        });

        vm.startPrank(_owner);
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.mevRestakedETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.mevCapitalETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.hashKeyCloudETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.renzoRestakedETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(vaultsAddressesDeployed.re7LabsETH.vault, stakerRewardsParams);
        ecosystemEntities.middleware.registerSharedVault(vaultsAddressesDeployed.cp0xLrtETH.vault, stakerRewardsParams);
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.gauntletRestakedWstETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.re7LabsRestakingETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.gauntletRestakedSwETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.gauntletRestakedRETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerSharedVault(
            vaultsAddressesDeployed.gauntletRestakedWBETH.vault, stakerRewardsParams
        );
        ecosystemEntities.middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator3, abi.encode(OPERATOR3_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator5, abi.encode(OPERATOR5_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator6, abi.encode(OPERATOR6_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator7, abi.encode(OPERATOR7_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator8, abi.encode(OPERATOR8_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator9, abi.encode(OPERATOR9_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator10, abi.encode(OPERATOR10_KEY), address(0));
        vm.stopPrank();
    }

    function _registerOperator(address _operator, address _network, address _vault, address vaultManager) public {
        (
            ,
            address operatorRegistryAddress,
            ,
            ,
            address operatorNetworkOptInServiceAddress,
            address operatorVaultOptInServiceAddress,
            ,
            ,
        ) = helperConfig.activeNetworkConfig();

        IOperatorRegistry operatorRegistry = IOperatorRegistry(operatorRegistryAddress);
        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);
        IOptInService operatorNetworkOptInService = IOptInService(operatorNetworkOptInServiceAddress);

        vm.startPrank(_operator);
        if (!operatorRegistry.isEntity(_operator)) {
            operatorRegistry.registerOperator();
        }
        operatorVaultOptInService.optIn(address(_vault));
        if (!operatorNetworkOptInService.isOptedIn(_operator, _network)) {
            operatorNetworkOptInService.optIn(_network);
        }
        if (vaultManager != address(0)) {
            vm.startPrank(vaultManager);
            IVault(_vault).setDepositorWhitelistStatus(_operator, true);
        }
        vm.stopPrank();
    }

    function _setLimitsAndShares(
        address _owner
    ) private {
        _setMaxNetworkLimits();
        _setNetworkLimits();
        _setOperatorShares();

        // Mock the oracle to return the correct conversion token
        vm.mockCall(
            oracle,
            abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),
            abi.encode(uint80(0), ORACLE_CONVERSION_TOKEN, uint256(0), uint256(0), uint80(0))
        );
        vm.mockCall(
            oracle, abi.encodeWithSelector(AggregatorV3Interface.decimals.selector), abi.encode(uint8(ORACLE_DECIMALS))
        );
    }

    function _setMaxNetworkLimits() private {
        vm.startPrank(tanssi);
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevRestakedETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.hashKeyCloudETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.renzoRestakedETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsETH.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsAddressesDeployed.cp0xLrtETH.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWstETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsRestakingETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setMaxNetworkLimit(
            0, MAX_NETWORK_LIMIT
        );
        vm.stopPrank();
    }

    function _setNetworkLimits() private {
        vm.startPrank(0xA1E38210B06A05882a7e7Bfe167Cd67F07FA234A);
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevRestakedETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x8989e3f949df80e8eFcbf3372F082699b93E5C09);
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x323B1370eC7D17D0c70b2CbebE052b9ed0d8A289);
        INetworkRestakeDelegator(vaultsAddressesDeployed.hashKeyCloudETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x6e5CaD73D00Bc8340f38afb61Fc5E34f7193F599);
        INetworkRestakeDelegator(vaultsAddressesDeployed.renzoRestakedETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0xE86399fE6d7007FdEcb08A2ee1434Ee677a04433);
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );
        vm.startPrank(0xD1f59ba974E828dF68cB2592C16b967B637cB4e4);
        IVault cp0xVault = IVault(vaultsAddressesDeployed.cp0xLrtETH.vault);
        INetworkRestakeDelegator(vaultsAddressesDeployed.cp0xLrtETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );
        if (cp0xVault.depositLimit() == cp0xVault.totalStake()) {
            cp0xVault.setDepositLimit(cp0xVault.depositLimit() * 10);
        }

        vm.startPrank(0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1);
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWstETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0xE86399fE6d7007FdEcb08A2ee1434Ee677a04433);
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsRestakingETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1);
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1);
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        vm.startPrank(0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1);
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setNetworkLimit(
            tanssi.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );
    }

    function _setOperatorShares() private {
        // Vault Manager for mevRestakedETH
        vm.startPrank(0xA1E38210B06A05882a7e7Bfe167Cd67F07FA234A);
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevRestakedETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevRestakedETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevRestakedETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for mevCapitalETH
        vm.startPrank(0x8989e3f949df80e8eFcbf3372F082699b93E5C09);
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.mevCapitalETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for hashKeyCloudETH
        vm.startPrank(0x323B1370eC7D17D0c70b2CbebE052b9ed0d8A289);
        INetworkRestakeDelegator(vaultsAddressesDeployed.hashKeyCloudETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.hashKeyCloudETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for renzoRestakedETH
        vm.startPrank(0x6e5CaD73D00Bc8340f38afb61Fc5E34f7193F599);
        INetworkRestakeDelegator(vaultsAddressesDeployed.renzoRestakedETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator7, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.renzoRestakedETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for re7LabsETH
        vm.startPrank(0xE86399fE6d7007FdEcb08A2ee1434Ee677a04433);
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for re7LabsRestakingETH
        vm.startPrank(0xE86399fE6d7007FdEcb08A2ee1434Ee677a04433);
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsRestakingETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsRestakingETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator7, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.re7LabsRestakingETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for cp0xLrtETH
        vm.startPrank(0xD1f59ba974E828dF68cB2592C16b967B637cB4e4);
        INetworkRestakeDelegator(vaultsAddressesDeployed.cp0xLrtETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.cp0xLrtETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator9, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.cp0xLrtETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // Vault Manager for gauntletRestaked
        vm.startPrank(0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1);
        // swETH
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator4, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator8, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedSwETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // wstETH
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWstETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWstETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator8, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWstETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // rETH
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator7, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator9, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedRETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );

        // wBETH
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator5, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator6, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator8, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator9, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultsAddressesDeployed.gauntletRestakedWBETH.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator10, OPERATOR_SHARE
        );
        vm.stopPrank();
    }

    function _setupGateway() private {
        AgentExecutor executor = new AgentExecutor();
        gatewayLogic = new MockGateway(
            address(0), address(executor), bridgeHubParaID, bridgeHubAgentID, foreignTokenDecimals, maxDestinationFee
        );
        Gateway.Config memory config = Gateway.Config({
            mode: OperatingMode.Normal,
            deliveryCost: outboundFee,
            registerTokenFee: registerTokenFee,
            assetHubParaID: assetHubParaID,
            assetHubAgentID: assetHubAgentID,
            assetHubCreateAssetFee: createTokenFee,
            assetHubReserveTransferFee: sendTokenFee,
            exchangeRate: exchangeRate,
            multiplier: multiplier,
            rescueOperator: 0x4B8a782D4F03ffcB7CE1e95C5cfe5BFCb2C8e967
        });
        gateway = new GatewayProxy(address(gatewayLogic), abi.encode(config));
        MockGateway(address(gateway)).setCommitmentsAreVerified(true);

        SetOperatingModeParams memory params = SetOperatingModeParams({mode: OperatingMode.Normal});
        MockGateway(address(gateway)).setOperatingModePublic(abi.encode(params));

        IOGateway(address(gateway)).setMiddleware(address(ecosystemEntities.middleware));
        vm.prank(tanssi);
        ecosystemEntities.middleware.setGateway(address(gateway));
    }

    function _saveStakeBeforeDepositing() private {
        vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.mevRestakedETH.vault).activeStake();
        vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.mevCapitalETH.vault).activeStake();
        vaultStakeBeforeDeposit.hashKeyCloudStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.hashKeyCloudETH.vault).activeStake();
        vaultStakeBeforeDeposit.renzoRestakedStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.renzoRestakedETH.vault).activeStake();
        vaultStakeBeforeDeposit.re7LabsStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.re7LabsETH.vault).activeStake();
        vaultStakeBeforeDeposit.re7LabsRestakingStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault).activeStake();
        vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.cp0xLrtETH.vault).activeStake();
        vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.gauntletRestakedWstETH.vault).activeStake();
        vaultStakeBeforeDeposit.gauntletRestakedCbStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault).activeStake();
        vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault).activeStake();
        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault).activeStake();
        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit =
            IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault).activeStake();
    }

    function _getMaximumAvailableStakeForVault(
        address delegator,
        uint256 vaultActiveStake
    ) private view returns (uint256 maximumAvailableStake) {
        maximumAvailableStake =
            Math.min(INetworkRestakeDelegator(delegator).networkLimit(tanssi.subnetwork(0)), vaultActiveStake);
    }

    function _calculateOperatorPower1() private view returns (uint256 operatorPower1) {
        operatorPower1 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.mevRestakedETH.delegator,
                    vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_RESTAKED
                ),
                TOTAL_SHARES_MEV_RESTAKED
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.mevCapitalETH.delegator,
                        vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                    ),
                    TOTAL_SHARES_MEV_CAPITAL
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.hashKeyCloudETH.delegator,
                        vaultStakeBeforeDeposit.hashKeyCloudStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_HASH_KEY_CLOUD
                    ),
                    TOTAL_SHARES_HASH_KEY_CLOUD
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower2() private view returns (uint256 operatorPower2) {
        operatorPower2 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.mevCapitalETH.delegator,
                    vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                ),
                TOTAL_SHARES_MEV_CAPITAL
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower3() private view returns (uint256 operatorPower3) {
        operatorPower3 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.re7LabsRestakingETH.delegator,
                    vaultStakeBeforeDeposit.gauntletRestakedCbStakeBeforeDeposit
                        + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
                ),
                TOTAL_SHARES_RE7_LABS_RESTAKING
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower4() private view returns (uint256 operatorPower4) {
        operatorPower4 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.gauntletRestakedSwETH.delegator,
                    vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
                        + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                ),
                TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
            )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower5() private view returns (uint256 operatorPower5) {
        operatorPower5 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                    vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit + OPERATOR_STAKE * 2
                ),
                TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
            )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower6() private view returns (uint256 operatorPower6) {
        operatorPower6 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.mevRestakedETH.delegator,
                    vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                ),
                TOTAL_SHARES_MEV_RESTAKED
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.mevCapitalETH.delegator,
                        vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                    ),
                    TOTAL_SHARES_MEV_CAPITAL
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.cp0xLrtETH.delegator,
                        vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
                    ),
                    TOTAL_SHARES_CP0X_LRT
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWstETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedSwETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower7() private view returns (uint256 operatorPower7) {
        operatorPower7 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.renzoRestakedETH.delegator,
                    vaultStakeBeforeDeposit.renzoRestakedStakeBeforeDeposit
                        + OPERATOR_STAKE * TOTAL_SHARES_RENZO_RESTAKED
                ),
                TOTAL_SHARES_RENZO_RESTAKED
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.re7LabsRestakingETH.delegator,
                        vaultStakeBeforeDeposit.re7LabsRestakingStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
                    ),
                    TOTAL_SHARES_RE7_LABS_RESTAKING
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower8() private view returns (uint256 operatorPower8) {
        operatorPower8 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.gauntletRestakedWstETH.delegator,
                    vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
                        + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
                ),
                TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedSwETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower9() private view returns (uint256 operatorPower9) {
        operatorPower9 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.cp0xLrtETH.delegator,
                    vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
                ),
                TOTAL_SHARES_CP0X_LRT
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedSwETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    function _calculateOperatorPower10() private view returns (uint256 operatorPower10) {
        operatorPower10 = (
            OPERATOR_SHARE.mulDiv(
                _getMaximumAvailableStakeForVault(
                    vaultsAddressesDeployed.mevRestakedETH.delegator,
                    vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                ),
                TOTAL_SHARES_MEV_RESTAKED
            )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.mevCapitalETH.delegator,
                        vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
                    ),
                    TOTAL_SHARES_MEV_CAPITAL
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.hashKeyCloudETH.delegator,
                        vaultStakeBeforeDeposit.hashKeyCloudStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_HASH_KEY_CLOUD
                    ),
                    TOTAL_SHARES_HASH_KEY_CLOUD
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.cp0xLrtETH.delegator,
                        vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
                    ),
                    TOTAL_SHARES_CP0X_LRT
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.re7LabsRestakingETH.delegator,
                        vaultStakeBeforeDeposit.re7LabsRestakingStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
                    ),
                    TOTAL_SHARES_RE7_LABS_RESTAKING
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.renzoRestakedETH.delegator,
                        vaultStakeBeforeDeposit.renzoRestakedStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_RENZO_RESTAKED
                    ),
                    TOTAL_SHARES_RENZO_RESTAKED
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.re7LabsETH.delegator,
                        vaultStakeBeforeDeposit.re7LabsStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS
                    ),
                    TOTAL_SHARES_RE7_LABS
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWstETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedRETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedWBETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
                )
                + OPERATOR_SHARE.mulDiv(
                    _getMaximumAvailableStakeForVault(
                        vaultsAddressesDeployed.gauntletRestakedSwETH.delegator,
                        vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
                            + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                    ),
                    TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
                )
        ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    }

    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        (, address operatorRegistryAddress,, address vaultFactoryAddress,,,,,) = helperConfig.activeNetworkConfig();

        assertEq(OBaseMiddlewareReader(address(ecosystemEntities.middleware)).NETWORK(), tanssi);
        assertEq(
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).OPERATOR_REGISTRY(), operatorRegistryAddress
        );
        assertEq(OBaseMiddlewareReader(address(ecosystemEntities.middleware)).VAULT_REGISTRY(), vaultFactoryAddress);
        assertEq(EpochCapture(address(ecosystemEntities.middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(OBaseMiddlewareReader(address(ecosystemEntities.middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(OBaseMiddlewareReader(address(ecosystemEntities.middleware)).subnetworksLength(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 10);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[3].operator, operator4);
        assertEq(operatorVaultPairs[4].operator, operator5);
        assertEq(operatorVaultPairs[5].operator, operator6);
        assertEq(operatorVaultPairs[6].operator, operator7);
        assertEq(operatorVaultPairs[7].operator, operator8);
        assertEq(operatorVaultPairs[8].operator, operator9);
        assertEq(operatorVaultPairs[9].operator, operator10);
        assertEq(operatorVaultPairs[0].vaults.length, 3);
        assertEq(operatorVaultPairs[1].vaults.length, 3);
        assertEq(operatorVaultPairs[2].vaults.length, 2);
        assertEq(operatorVaultPairs[3].vaults.length, 1);
        assertEq(operatorVaultPairs[4].vaults.length, 1);
    }

    function testOperatorsAreRegisteredAfterOneEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 10);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 10);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[3].operator, operator4);
        assertEq(operatorVaultPairs[4].operator, operator5);
        assertEq(operatorVaultPairs[5].operator, operator6);
        assertEq(operatorVaultPairs[6].operator, operator7);
        assertEq(operatorVaultPairs[7].operator, operator8);
        assertEq(operatorVaultPairs[8].operator, operator9);
        assertEq(operatorVaultPairs[9].operator, operator10);
        assertEq(operatorVaultPairs[0].vaults.length, 3);
        assertEq(operatorVaultPairs[1].vaults.length, 3);
        assertEq(operatorVaultPairs[2].vaults.length, 2);
        assertEq(operatorVaultPairs[3].vaults.length, 1);
        assertEq(operatorVaultPairs[4].vaults.length, 1);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 previousEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].power, validatorsPreviousEpoch[0].power);
        assertEq(validators[1].power, validatorsPreviousEpoch[1].power);
        assertEq(validators[2].power, validatorsPreviousEpoch[2].power);
        assertEq(validators[0].key, validatorsPreviousEpoch[0].key);
        assertEq(validators[1].key, validatorsPreviousEpoch[1].key);
        assertEq(validators[2].key, validatorsPreviousEpoch[2].key);
    }

    function testWithdrawForOperator1() public {
        IVault vaultMevRestaked = IVault(vaultsAddressesDeployed.mevRestakedETH.vault);
        IVault vaultMevCapital = IVault(vaultsAddressesDeployed.mevCapitalETH.vault);
        IVault vaultHashkeyCloud = IVault(vaultsAddressesDeployed.hashKeyCloudETH.vault);
        uint256 currentEpochMevRestaked = vaultMevRestaked.currentEpoch();
        uint256 currentEpochMevCapital = vaultMevCapital.currentEpoch();
        uint256 currentEpochHashkeyCloud = vaultHashkeyCloud.currentEpoch();

        uint256 currentEpochMevRestakedEpochDuration = vaultMevRestaked.epochDuration();
        uint256 currentEpochMevCapitalEpochDuration = vaultMevCapital.epochDuration();
        uint256 currentEpochHashkeyCloudEpochDuration = vaultHashkeyCloud.epochDuration();

        uint256 currentTimestamp = block.timestamp;

        vm.startPrank(operator);
        vaultMevRestaked.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);
        vaultMevCapital.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);
        vaultHashkeyCloud.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(currentTimestamp + currentEpochMevRestakedEpochDuration * 2 + 1);
        currentEpochMevRestaked = vaultMevRestaked.currentEpoch();
        vaultMevRestaked.claim(operator, currentEpochMevRestaked - 1);

        vm.warp(currentTimestamp + currentEpochMevCapitalEpochDuration * 2 + 1);
        currentEpochMevCapital = vaultMevCapital.currentEpoch();
        vaultMevCapital.claim(operator, currentEpochMevCapital - 1);

        vm.warp(currentTimestamp + currentEpochHashkeyCloudEpochDuration * 2 + 1);
        currentEpochHashkeyCloud = vaultHashkeyCloud.currentEpoch();
        vaultHashkeyCloud.claim(operator, currentEpochHashkeyCloud - 1);

        assertEq(
            ecosystemEntities.wstETH.balanceOf(operator),
            OPERATOR_INITIAL_BALANCE * 4 - OPERATOR_STAKE * 3 + DEFAULT_WITHDRAW_AMOUNT * 3
        );
    }

    function testWithdrawForOperator2() public {
        IVault vaultMevCapital = IVault(vaultsAddressesDeployed.mevCapitalETH.vault);
        IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault);
        IVault vaultGauntletRestakedWBETH = IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault);

        uint256 currentEpochMevCapital = vaultMevCapital.currentEpoch();
        uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        uint256 currentEpochGauntletRestakedWBETH = vaultGauntletRestakedWBETH.currentEpoch();

        uint256 currentEpochMevCapitalEpochDuration = vaultMevCapital.epochDuration();
        uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();
        uint256 currentEpochGauntletRestakedWBETHEpochDuration = vaultGauntletRestakedWBETH.epochDuration();

        uint256 currentTimestamp = block.timestamp;

        vm.startPrank(operator2);
        vaultMevCapital.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);
        vaultGauntletRestaked.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);
        vaultGauntletRestakedWBETH.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(currentTimestamp + currentEpochMevCapitalEpochDuration * 2 + 1);
        currentEpochMevCapital = vaultMevCapital.currentEpoch();
        vaultMevCapital.claim(operator2, currentEpochMevCapital - 1);

        vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
        currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        vaultGauntletRestaked.claim(operator2, currentEpochGauntletRestaked - 1);

        vm.warp(currentTimestamp + currentEpochGauntletRestakedWBETHEpochDuration * 2 + 1);
        currentEpochGauntletRestakedWBETH = vaultGauntletRestakedWBETH.currentEpoch();
        vaultGauntletRestakedWBETH.claim(operator2, currentEpochGauntletRestakedWBETH - 1);

        assertEq(
            ecosystemEntities.wstETH.balanceOf(operator2),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
        assertEq(
            ecosystemEntities.rETH.balanceOf(operator2),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
        assertEq(
            ecosystemEntities.wBETH.balanceOf(operator2),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
    }

    function testWithdrawForOperator3() public {
        IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployed.gauntletRestakedRETH.vault);
        IVault vaultRe7LabsRestaked = IVault(vaultsAddressesDeployed.re7LabsRestakingETH.vault);

        uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        uint256 currentEpochRe7LabsRestaked = vaultRe7LabsRestaked.currentEpoch();

        uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();
        uint256 currentEpochRe7LabsRestakedEpochDuration = vaultRe7LabsRestaked.epochDuration();

        uint256 currentTimestamp = block.timestamp;

        vm.startPrank(operator3);
        vaultGauntletRestaked.withdraw(operator3, DEFAULT_WITHDRAW_AMOUNT);
        vaultRe7LabsRestaked.withdraw(operator3, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
        currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        vaultGauntletRestaked.claim(operator3, currentEpochGauntletRestaked - 1);

        vm.warp(currentTimestamp + currentEpochRe7LabsRestakedEpochDuration * 2 + 1);
        currentEpochRe7LabsRestakedEpochDuration = vaultRe7LabsRestaked.currentEpoch();
        vaultRe7LabsRestaked.claim(operator3, currentEpochRe7LabsRestakedEpochDuration - 1);

        assertEq(
            ecosystemEntities.rETH.balanceOf(operator3),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
        assertEq(
            ecosystemEntities.wstETH.balanceOf(operator3),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
    }

    function testWithdrawForOperator4() public {
        IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployed.gauntletRestakedSwETH.vault);

        uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();

        uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();

        uint256 currentTimestamp = block.timestamp;

        vm.startPrank(operator4);
        vaultGauntletRestaked.withdraw(operator4, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
        currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        vaultGauntletRestaked.claim(operator4, currentEpochGauntletRestaked - 1);

        assertEq(
            ecosystemEntities.swETH.balanceOf(operator4),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
    }

    function testWithdrawForOperator5() public {
        IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployed.gauntletRestakedWBETH.vault);

        uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();

        uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();

        uint256 currentTimestamp = block.timestamp;

        vm.startPrank(operator5);
        vaultGauntletRestaked.withdraw(operator5, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
        currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
        vaultGauntletRestaked.claim(operator5, currentEpochGauntletRestaked - 1);

        assertEq(
            ecosystemEntities.wBETH.balanceOf(operator5),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
        );
    }

    function testOperatorPower() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);

        uint256 operatorPower1 = _calculateOperatorPower1();
        uint256 operatorPower2 = _calculateOperatorPower2();
        uint256 operatorPower3 = _calculateOperatorPower3();
        uint256 operatorPower4 = _calculateOperatorPower4();
        uint256 operatorPower5 = _calculateOperatorPower5();

        assertEq(validators[0].power, operatorPower1);
        assertEq(validators[1].power, operatorPower2);
        assertEq(validators[2].power, operatorPower3);
        assertEq(validators[3].power, operatorPower4);
        assertEq(validators[4].power, operatorPower5);
    }

    function testPauseAndUnregisterOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        vm.startPrank(tanssi);
        ecosystemEntities.middleware.pauseOperator(operator);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);

        ecosystemEntities.middleware.unregisterOperator(operator);
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 9); // One less operator

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        ecosystemEntities.middleware.registerOperator(operator, abi.encode(bytes32(uint256(12))), address(0));
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 10); // One less operator
    }

    function testPauseAndUnpausingOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);

        vm.startPrank(tanssi);
        ecosystemEntities.middleware.pauseOperator(operator);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 9); // One less operator

        ecosystemEntities.middleware.unpauseOperator(operator);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 10);
    }

    function testUpkeep() public {
        vm.prank(owner);
        ecosystemEntities.middleware.setForwarder(forwarder);
        // It's not needed, it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");

        vm.prank(offlineKeepers);
        (bool upkeepNeeded, bytes memory performData) = ecosystemEntities.middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        uint256 beforeGas = gasleft();
        (upkeepNeeded, performData) = ecosystemEntities.middleware.checkUpkeep(hex"");
        uint256 afterGas = gasleft();

        assertLt(beforeGas - afterGas, 10 ** 7); // Check that gas is lower than 10M
        assertEq(upkeepNeeded, true);

        bytes32[] memory sortedKeys = abi.decode(performData, (bytes32[]));
        assertEq(sortedKeys.length, 10);

        vm.prank(forwarder);
        vm.expectEmit(true, false, false, false);
        emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
        ecosystemEntities.middleware.performUpkeep(performData);
    }

    function testMiddlewareIsUpgradeable() public {
        address operatorRewardsAddress = makeAddr("operatorRewards");
        address stakerRewardsFactoryAddress = makeAddr("stakerRewardsFactory");
        Middleware middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);

        vm.startPrank(owner);
        assertEq(ecosystemEntities.middleware.VERSION(), 1);

        MiddlewareV2 middlewareImplV2 = new MiddlewareV2();
        bytes memory emptyBytes = hex"";
        ecosystemEntities.middleware.upgradeToAndCall(address(middlewareImplV2), emptyBytes);

        assertEq(ecosystemEntities.middleware.VERSION(), 2);

        vm.expectRevert(); //Function doesn't exists
        ecosystemEntities.middleware.setGateway(address(gateway));

        ecosystemEntities.middleware.upgradeToAndCall(address(middlewareImpl), emptyBytes);
        assertEq(ecosystemEntities.middleware.VERSION(), 1);

        vm.expectRevert(IMiddleware.Middleware__AlreadySet.selector);
        ecosystemEntities.middleware.setGateway(address(gateway));
        assertEq(ecosystemEntities.middleware.getGateway(), address(gateway));
    }

    // function testSlashingOnOperator2AndVetoingSlash() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
    //         _prepareSlashingTest();

    //     uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

    //     vm.prank(address(gateway));
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

    //     vm.prank(resolver1);
    //     ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");
    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator2PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
    //     (uint256 totalOperator3PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

    //     assertEq(validators[1].power, totalOperator2PowerAfter);
    //     assertEq(validators[2].power, totalOperator3PowerAfter);
    // }

    // function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
    //         _prepareSlashingTest();

    //     // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
    //     uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

    //     vm.prank(address(gateway));
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

    //     vm.warp(block.timestamp + VETO_DURATION);
    //     vm.prank(address(ecosystemEntities.middleware));
    //     ecosystemEntities.vetoSlasher.executeSlash(0, hex"");
    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator2PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
    //     (uint256 totalOperator3PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

    //     assertEq(validators[1].power, totalOperator2PowerAfter);
    //     assertEq(validators[2].power, totalOperator3PowerAfter);
    // }

    // function testSlashingOnOperator3AndVetoingSlash() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,, uint256 powerFromSharesOperator3) =
    //         _prepareSlashingTest();

    //     // We only take half of the operator3 shares, since only its participation on vaultSlashable will be slashed, regular vault isn't affected
    //     uint256 slashingPower = (SLASHING_FRACTION * (powerFromSharesOperator3 / 2)) / PARTS_PER_BILLION;

    //     vm.prank(gateway);
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

    //     vm.prank(resolver1);
    //     ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");

    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator2PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
    //     (uint256 totalOperator3PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

    //     assertEq(validators[1].power, totalOperator2PowerAfter);
    //     assertEq(validators[2].power, totalOperator3PowerAfter);
    // }

    // function testSlashingOnOperator3AndExecuteSlashOnVetoVault() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,, uint256 powerFromSharesOperator3) =
    //         _prepareSlashingTest();

    //     // We only take half of the operator3 shares, since only its participation on vaultSlashable will be slashed, regular vault isn't affected
    //     uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator3 / 2) / PARTS_PER_BILLION;

    //     vm.prank(gateway);
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

    //     vm.warp(block.timestamp + VETO_DURATION);
    //     vm.prank(address(ecosystemEntities.middleware));
    //     ecosystemEntities.vetoSlasher.executeSlash(0, hex"");

    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator2PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
    //     (uint256 totalOperator3PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

    //     assertEq(validators[1].power, totalOperator2PowerAfter);
    //     assertEq(validators[2].power, totalOperator3PowerAfter);
    // }

    // function testSlashingAndPausingVault() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,,) = _prepareSlashingTest();

    //     vm.prank(owner);
    //     ecosystemEntities.middleware.pauseSharedVault(vaultAddresses.vaultSlashable);

    //     vm.prank(gateway);
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator2PowerAfter,) = _calculateOperatorPower(0, totalFullRestakePower, 0);
    //     (uint256 totalOperator3PowerAfter,) = _calculateOperatorPower(totalPowerVault, totalFullRestakePower, 0);

    //     assertEq(validators[1].power, totalOperator2PowerAfter);
    //     assertEq(validators[2].power, totalOperator3PowerAfter);
    // }

    // function testSlashingAndPausingOperator() public {
    //     (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
    //         _prepareSlashingTest();

    //     vm.prank(owner);
    //     ecosystemEntities.middleware.pauseOperator(operator2);

    //     // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
    //     uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

    //     vm.prank(gateway);
    //     ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

    //     vm.warp(block.timestamp + SLASHING_WINDOW + 1);
    //     uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

    //     (uint256 totalOperator3PowerAfter,) =
    //         _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
    //     // Index is 1 instead of 2 because operator2 was paused
    //     assertEq(validators[1].power, totalOperator3PowerAfter);
    // }

    // function testOperatorsOnlyInTanssiNetwork() public {
    //     (
    //         ,
    //         address operatorRegistryAddress,
    //         address networkRegistryAddress,
    //         address vaultFactoryAddress,
    //         address operatorNetworkOptInServiceAddress,
    //         ,
    //         address networkMiddlewareServiceAddress,
    //         ,
    //     ) = helperConfig.activeNetworkConfig();

    //     address operator4 = makeAddr("operator4");
    //     address network2 = makeAddr("network2");

    //     bytes32 OPERATOR4_KEY = bytes32(uint256(4));
    //     deal(address(ecosystemEntities.wstETH), operator4, OPERATOR_INITIAL_BALANCE);

    //     //Middleware 2 Deployment
    //     vm.startPrank(network2);
    //     INetworkRegistry(networkRegistryAddress).registerNetwork();
    //     INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);

    //     vm.startPrank(owner);
    //     INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
    //         network2.subnetwork(0), operator4, OPERATOR_SHARE
    //     );
    //     INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(
    //         network2.subnetwork(0), OPERATOR_NETWORK_LIMIT
    //     );
    //     _registerOperator(operator4, network2, address(ecosystemEntities.vault));

    //     vm.startPrank(network2);

    //     Middleware _middlewareImpl = _getMiddlewareImpl(network2, vaultFactoryAddress, networkMiddlewareServiceAddress);
    //     Middleware middleware2 = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
    //     vm.startPrank(owner);
    //     ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
    //     operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware2));
    //     operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware2));

    //     vm.startPrank(network2);
    //     address readHelper = address(new OBaseMiddlewareReader());
    //     IMiddleware.InitParams memory params = IMiddleware.InitParams({
    //         network: network2,
    //         operatorRegistry: operatorRegistryAddress,
    //         vaultRegistry: vaultFactoryAddress,
    //         operatorNetworkOptIn: operatorNetworkOptInServiceAddress,
    //         owner: network2,
    //         epochDuration: NETWORK_EPOCH_DURATION,
    //         slashingWindow: SLASHING_WINDOW,
    //         reader: readHelper
    //     });
    //     middleware2.initialize(params);

    //     INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(address(middleware2));
    //     IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
    //         adminFee: 0,
    //         defaultAdminRoleHolder: network2,
    //         adminFeeClaimRoleHolder: network2,
    //         adminFeeSetRoleHolder: network2
    //     });
    //     middleware2.registerSharedVault(address(ecosystemEntities.vault), stakerRewardsParams);
    //     middleware2.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
    //     vm.stopPrank();

    //     vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

    //     uint48 middlewareCurrentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     Middleware.OperatorVaultPair[] memory operatorVaultPairs =
    //         OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(middlewareCurrentEpoch);

    //     uint48 middleware2CurrentEpoch = middleware2.getCurrentEpoch();
    //     Middleware.OperatorVaultPair[] memory operator2VaultPairs =
    //         OBaseMiddlewareReader(address(middleware2)).getOperatorVaultPairs(middleware2CurrentEpoch);

    //     assertEq(operator2VaultPairs.length, 1);
    //     assertEq(operator2VaultPairs[0].operator, operator4);
    //     assertEq(operator2VaultPairs[0].vaults.length, 1);

    //     for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
    //         assert(operatorVaultPairs[i].operator != operator4);
    //     }
    // }

    // function _getMiddlewareImpl(
    //     address network,
    //     address vaultFactoryAddress,
    //     address networkMiddlewareServiceAddress
    // ) private returns (Middleware middlewareImpl) {
    //     DeployRewards deployRewards = new DeployRewards();
    //     deployRewards.setIsTest(true);

    //     operatorRewardsAddress =
    //         deployRewards.deployOperatorRewardsContract(network, networkMiddlewareServiceAddress, 5000, owner);

    //     address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
    //         vaultFactoryAddress, networkMiddlewareServiceAddress, operatorRewardsAddress, owner
    //     );

    //     middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
    // }

    function _prepareSlashingTest()
        public
        returns (uint48 currentEpoch, Middleware.ValidatorData[] memory validators)
    {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
    }
}
