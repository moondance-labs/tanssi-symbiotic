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
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
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
    uint256 public constant MIN_DEPOSIT = 10 ether; // 10 ETH

    uint256 public constant OPERATOR_SHARE = 1;
    uint256 public constant OPERATOR_SHARE_RE7_LABS = 10 ether;
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

    address public admin;
    address public tanssi;

    uint256 public constant PIER_TWO_VAULTS = 10;
    uint256 public constant P2P_VAULTS = 8;
    uint256 public constant NODE_INFRA = 3;
    uint256 public constant BLOCKSCAPE_VAULTS = 4;
    uint256 public constant QUANT_NODE_VAULTS = 1;
    uint256 public constant NODE_MONSTER_VAULTS = 1;
    uint256 public constant BLOCK_BONES_VAULTS = 1;
    uint256 public constant CP0X_STAKRSPACE_VAULTS = 2;
    uint256 public constant HASHKEY_CLOUD_VAULTS = 1;
    uint256 public constant ALCHEMY_VAULTS = 8;
    uint256 public constant OPSLAYER_VAULTS = 1;

    uint256 public constant TOTAL_OPERATORS = 11;

    address public constant VAULT_MANAGER_COMMON = 0x9437B2a8cF3b69D782a61f9814baAbc172f72003;

    address public constant VAULT_MANAGER_MEVRESTAKEDETH = 0xA1E38210B06A05882a7e7Bfe167Cd67F07FA234A;
    address public constant VAULT_MANAGER_MEVCAPITALETH = 0x8989e3f949df80e8eFcbf3372F082699b93E5C09;
    address public constant VAULT_MANAGER_HASHKEYCLOUDETH = 0x323B1370eC7D17D0c70b2CbebE052b9ed0d8A289;
    address public constant VAULT_MANAGER_RENZORESTAKEDETH = 0x6e5CaD73D00Bc8340f38afb61Fc5E34f7193F599;
    address public constant VAULT_MANAGER_RE7LABS = 0xE86399fE6d7007FdEcb08A2ee1434Ee677a04433;
    address public constant VAULT_MANAGER_CP0XLRTETH = 0xD1f59ba974E828dF68cB2592C16b967B637cB4e4;
    address public constant VAULT_MANAGER_GAUNTLET = 0x059Ae3F8a1EaDDAAb34D0A74E8Eb752c848062d1;
    address public constant VAULT_MANAGER_ETHERFIWSTETH = 0x47482dA197719f2CE0BAeBB7F72D1d7C1D6cc8bD;
    address public constant VAULT_MANAGER_RESTAKEDLSETHVAULT = 0x8989e3f949df80e8eFcbf3372F082699b93E5C09;
    address public constant VAULT_MANAGER_OPSLAYER = 0xf409021Fa7E769837162346CFA8d1eF4DAa77585;

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

    struct VaultStakeBeforeDepositA {
        uint256 mevRestakedETH;
        uint256 mevCapitalETH;
        uint256 hashKeyCloudETH;
        uint256 renzoRestakedETH;
        uint256 re7LabsETH;
        uint256 re7LabsRestakingETH;
        uint256 cp0xLrtETH;
        uint256 etherfiwstETH;
        uint256 restakedLsETHVault;
        uint256 opslayer;
    }

    struct VaultStakeBeforeDepositB {
        uint256 gauntletRestakedWstETH;
        uint256 gauntletRestakedSwETH;
        uint256 gauntletRestakedRETH;
        uint256 gauntletRestakedWBETH;
        uint256 gauntletRestakedcBETH;
    }

    struct VaultTotalStakeA {
        uint256 mevRestakedETH;
        uint256 mevCapitalETH;
        uint256 hashKeyCloudETH;
        uint256 renzoRestakedETH;
        uint256 re7LabsETH;
        uint256 re7LabsRestakingETH;
        uint256 cp0xLrtETH;
        uint256 etherfiwstETH;
        uint256 restakedLsETHVault;
        uint256 opslayer;
    }

    struct VaultTotalStakeB {
        uint256 gauntletRestakedWstETH;
        uint256 gauntletRestakedSwETH;
        uint256 gauntletRestakedRETH;
        uint256 gauntletRestakedWBETH;
        uint256 gauntletRestakedcBETH;
    }

    struct EcosystemEntity {
        Middleware middleware;
        IDefaultCollateral wstETH;
        IDefaultCollateral rETH;
        IDefaultCollateral swETH;
        IDefaultCollateral wBETH;
        IDefaultCollateral LsETH;
        IDefaultCollateral cbETH;
    }

    EcosystemEntity public ecosystemEntities;

    HelperConfig.VaultsConfigA public vaultsAddressesDeployedA;
    HelperConfig.VaultsConfigB public vaultsAddressesDeployedB;
    HelperConfig.OperatorConfig public operators;

    VaultTotalStakeA public vaultTotalStakeA;
    VaultTotalStakeB public vaultTotalStakeB;

    VaultStakeBeforeDepositA public vaultStakeBeforeDepositA;
    VaultStakeBeforeDepositB public vaultStakeBeforeDepositB;

    function setUp() public {
        _getBaseInfrastructure();
        address[] memory activeOperators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).activeOperators();
        console2.log("Active operators before set up", activeOperators.length);

        _setLimitsAndShares(tanssi);
        _setupOperators();

        _registerEntitiesToMiddleware();
        _setupGateway();
        _saveStakeBeforeDepositing();

        /// ecosystemEntities.middleware.setCollateralToOracle(xxx, oracle); Called for each collateral: wstETH, rETH, swETH, wBETH, LsETH, cbETH
        vm.stopPrank();
    }

    function _getBaseInfrastructure() private {
        // Check if it's good for mainnet
        helperConfig = new HelperConfig();

        HelperConfig.TokensConfig memory tokensConfig;
        (, tokensConfig, vaultsAddressesDeployedA, vaultsAddressesDeployedB, operators) = helperConfig.getChainConfig();

        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/contract-addresses/tanssi.json");
        string memory json = vm.readFile(path);

        admin = abi.decode(vm.parseJson(json, "$.admin"), (address));
        tanssi = abi.decode(vm.parseJson(json, "$.tanssi"), (address));
        address middlewareAddress = abi.decode(vm.parseJson(json, "$.middleware"), (address));
        ecosystemEntities.middleware = Middleware(middlewareAddress);

        ecosystemEntities.wstETH = IDefaultCollateral(tokensConfig.wstETH);
        ecosystemEntities.rETH = IDefaultCollateral(tokensConfig.rETH);
        ecosystemEntities.swETH = IDefaultCollateral(tokensConfig.swETH);
        ecosystemEntities.wBETH = IDefaultCollateral(tokensConfig.wBETH);
        ecosystemEntities.LsETH = IDefaultCollateral(tokensConfig.LsETH);
        ecosystemEntities.cbETH = IDefaultCollateral(tokensConfig.cbETH);
    }

    function _setupOperators() private {
        // OPERATOR 1 - Pier Two

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.etherfiwstETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );

        _optInOperator(operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.renzoRestakedETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );

        // OPERATOR 2 - P2P

        _optInOperator(operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.etherfiwstETH, tanssi, address(0));

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );

        _optInOperator(operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.re7LabsRestakingETH, tanssi, address(0)
        );

        // OPERATOR 3 - Nodeinfra

        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );

        // OPERATOR 4 - Blockscape
        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );

        // OPERATOR 5 - Quant Node

        _optInOperator(operators.operator5QuantNode.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));

        // OPERATOR 6 - Node Monster

        _optInOperator(
            operators.operator6NodeMonster.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );

        // OPERATOR 7 - BlocknBones
        _optInOperator(
            operators.operator7BlockBones.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );

        // OPERATOR 8 - CP0X Stakrspace
        _optInOperator(
            operators.operator8CP0XStakrspace.evmAddress, vaultsAddressesDeployedA.cp0xLrtETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator8CP0XStakrspace.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );

        // OPERATOR 9 - Hashkey Cloud
        _optInOperator(
            operators.operator9HashkeyCloud.evmAddress, vaultsAddressesDeployedA.hashKeyCloudETH, tanssi, address(0)
        );

        // OPERATOR 10 - Alchemy

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );

        // OPERATOR 11 - Ops Layer

        _optInOperator(
            operators.operator11Opslayer.evmAddress, vaultsAddressesDeployedA.opslayer, tanssi, VAULT_MANAGER_OPSLAYER
        );
    }

    function _getTotalPower(
        address vault
    ) private view returns (uint256) {
        return (IVault(vault).activeStake() * uint256(ORACLE_CONVERSION_TOKEN)) / 10 ** ORACLE_DECIMALS;
    }

    function _depositToVault(IVault vault, address operator, uint256 amount, IERC20 collateral) public {
        deal(address(collateral), operator, amount);
        collateral.approve(address(vault), amount);
        vault.deposit(operator, amount);
    }

    function _registerEntitiesToMiddleware() public {
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: admin,
            adminFeeClaimRoleHolder: admin,
            adminFeeSetRoleHolder: admin
        });

        vm.startPrank(admin);
        address[] memory activeVaults = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).activeVaults();

        _registerVaultIfNotActive(vaultsAddressesDeployedA.mevRestakedETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.mevCapitalETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.hashKeyCloudETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.renzoRestakedETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.re7LabsETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.re7LabsRestakingETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.cp0xLrtETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.etherfiwstETH.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.restakedLsETHVault.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.opslayer.vault, activeVaults, stakerRewardsParams);

        _registerVaultIfNotActive(
            vaultsAddressesDeployedB.gauntletRestakedWstETH.vault, activeVaults, stakerRewardsParams
        );

        _registerVaultIfNotActive(
            vaultsAddressesDeployedB.gauntletRestakedWBETH.vault, activeVaults, stakerRewardsParams
        );

        _registerVaultIfNotActive(
            vaultsAddressesDeployedB.gauntletRestakedSwETH.vault, activeVaults, stakerRewardsParams
        );

        _registerVaultIfNotActive(
            vaultsAddressesDeployedB.gauntletRestakedRETH.vault, activeVaults, stakerRewardsParams
        );

        _registerVaultIfNotActive(
            vaultsAddressesDeployedB.gauntletRestakedcBETH.vault, activeVaults, stakerRewardsParams
        );

        _registerOperatorIfNeeded(operators.operator1PierTwo);
        _registerOperatorIfNeeded(operators.operator2P2P);
        _registerOperatorIfNeeded(operators.operator3Nodeinfra);
        _registerOperatorIfNeeded(operators.operator4Blockscape);
        _registerOperatorIfNeeded(operators.operator5QuantNode);
        _registerOperatorIfNeeded(operators.operator6NodeMonster);
        _registerOperatorIfNeeded(operators.operator7BlockBones);
        _registerOperatorIfNeeded(operators.operator8CP0XStakrspace);
        _registerOperatorIfNeeded(operators.operator9HashkeyCloud);
        _registerOperatorIfNeeded(operators.operator10Alchemy);
        _registerOperatorIfNeeded(operators.operator11Opslayer);

        vm.stopPrank();
    }

    function _registerOperatorIfNeeded(
        HelperConfig.OperatorData memory operator
    ) private {
        if (!OBaseMiddlewareReader(address(ecosystemEntities.middleware)).isOperatorRegistered(operator.evmAddress)) {
            console2.log("Registering operator", operator.evmAddress);
            ecosystemEntities.middleware.registerOperator(
                operator.evmAddress, abi.encode(operator.operatorKey), address(0)
            );
        }
    }

    function _registerVaultIfNotActive(
        address _vault,
        address[] memory _activeVaults,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) private {
        if (!OBaseMiddlewareReader(address(ecosystemEntities.middleware)).isVaultRegistered(_vault)) {
            console2.log("Registering vault", _vault);
            ecosystemEntities.middleware.registerSharedVault(_vault, stakerRewardsParams);
        }
    }

    function _optInOperator(
        address operator,
        HelperConfig.VaultTrifecta memory vaultTrifecta,
        address network,
        address vaultManager
    ) public {
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

        {
            bytes32 depositorWhitelistRole = 0x9c56d972d63cbb4195b3c1484691dfc220fa96a4c47e7b6613bd82a022029e06;

            if (vaultManager != address(0)) {
                vm.startPrank(vaultManager);
                IVault(vaultTrifecta.vault).setDepositorWhitelistStatus(operator, true);
            }
            // This is the vault manager for several vaults.
            else if (IAccessControl(vaultTrifecta.vault).hasRole(depositorWhitelistRole, VAULT_MANAGER_COMMON)) {
                // console2.log("Setting depositor whitelist status for", _operator, vaultTrifecta.vault);
                vm.startPrank(VAULT_MANAGER_COMMON);
                IVault(vaultTrifecta.vault).setDepositorWhitelistStatus(operator, true);
            }
        }

        vm.startPrank(operator);
        if (!operatorRegistry.isEntity(operator)) {
            console2.log("Registering operator", operator);
            operatorRegistry.registerOperator();
        }

        if (!operatorVaultOptInService.isOptedIn(operator, vaultTrifecta.vault)) {
            operatorVaultOptInService.optIn(vaultTrifecta.vault);
            console2.log("Opted in operator", operator, "to vault", vaultTrifecta.vault);
        }

        uint256 operatorStake = IBaseDelegator(vaultTrifecta.delegator).stakeAt(
            tanssi.subnetwork(0), operator, uint48(block.timestamp), new bytes(0)
        );
        if (operatorStake == 0) {
            IVault vault = IVault(vaultTrifecta.vault);
            console2.log("Operator", operator, "has no stake into vault", vaultTrifecta.vault);
            _depositToVault(vault, operator, MIN_DEPOSIT, IERC20(vault.collateral()));
        }

        if (!operatorNetworkOptInService.isOptedIn(operator, network)) {
            console2.log("Opting in operator", operator, "to network", network);
            operatorNetworkOptInService.optIn(network);
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

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.mevRestakedETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.mevCapitalETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.hashKeyCloudETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.renzoRestakedETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.re7LabsETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.re7LabsRestakingETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.cp0xLrtETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.etherfiwstETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.restakedLsETHVault.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedA.opslayer.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedB.gauntletRestakedRETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator, MAX_NETWORK_LIMIT);

        _setMaxNetworkLimitIfNeeded(vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator, MAX_NETWORK_LIMIT);

        vm.stopPrank();
    }

    function _setMaxNetworkLimitIfNeeded(address _delegator, uint256 _limit) private {
        INetworkRestakeDelegator delegator = INetworkRestakeDelegator(_delegator);

        if (delegator.maxNetworkLimit(tanssi.subnetwork(0)) == 0) {
            console2.log("Setting max network limit for", _delegator);
            delegator.setMaxNetworkLimit(0, _limit);
        }
    }

    function _setNetworkLimits() private {
        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_MEVRESTAKEDETH, vaultsAddressesDeployedA.mevRestakedETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_MEVCAPITALETH, vaultsAddressesDeployedA.mevCapitalETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_HASHKEYCLOUDETH, vaultsAddressesDeployedA.hashKeyCloudETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RENZORESTAKEDETH, vaultsAddressesDeployedA.renzoRestakedETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RE7LABS, vaultsAddressesDeployedA.re7LabsETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RE7LABS, vaultsAddressesDeployedA.re7LabsRestakingETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_ETHERFIWSTETH, vaultsAddressesDeployedA.etherfiwstETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RESTAKEDLSETHVAULT,
            vaultsAddressesDeployedA.restakedLsETHVault.delegator,
            OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_OPSLAYER, vaultsAddressesDeployedA.opslayer.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedRETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator, OPERATOR_NETWORK_LIMIT
        );
    }

    function _setNetworkLimitIfNeeded(address manager, address _delegator, uint256 _limit) private {
        vm.startPrank(manager);
        INetworkRestakeDelegator delegator = INetworkRestakeDelegator(_delegator);

        if (delegator.networkLimit(tanssi.subnetwork(0)) == 0) {
            console2.log("Setting network limit for", _delegator);
            uint256 maxLimit = delegator.maxNetworkLimit(tanssi.subnetwork(0));

            delegator.setNetworkLimit(tanssi.subnetwork(0), Math.min(maxLimit, _limit));
        }
        vm.stopPrank();
    }

    function _setOperatorShares() private {
        vm.startPrank(VAULT_MANAGER_CP0XLRTETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.cp0xLrtETH.delegator, operators.operator8CP0XStakrspace.evmAddress, OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_ETHERFIWSTETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.etherfiwstETH.delegator, operators.operator1PierTwo.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.etherfiwstETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_HASHKEYCLOUDETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.hashKeyCloudETH.delegator,
            operators.operator9HashkeyCloud.evmAddress,
            OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_MEVCAPITALETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevCapitalETH.delegator, operators.operator10Alchemy.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevCapitalETH.delegator, operators.operator3Nodeinfra.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevCapitalETH.delegator, operators.operator4Blockscape.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevCapitalETH.delegator,
            operators.operator8CP0XStakrspace.evmAddress,
            OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_MEVRESTAKEDETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevRestakedETH.delegator, operators.operator10Alchemy.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevRestakedETH.delegator, operators.operator1PierTwo.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevRestakedETH.delegator, operators.operator3Nodeinfra.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.mevRestakedETH.delegator, operators.operator4Blockscape.evmAddress, OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_RE7LABS);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE_RE7_LABS
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator,
            operators.operator4Blockscape.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator,
            operators.operator5QuantNode.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator,
            operators.operator6NodeMonster.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsETH.delegator,
            operators.operator7BlockBones.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );

        vm.startPrank(VAULT_MANAGER_RE7LABS);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.re7LabsRestakingETH.delegator,
            operators.operator2P2P.evmAddress,
            OPERATOR_SHARE_RE7_LABS
        );

        vm.startPrank(VAULT_MANAGER_RENZORESTAKEDETH);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.renzoRestakedETH.delegator, operators.operator10Alchemy.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.renzoRestakedETH.delegator, operators.operator1PierTwo.evmAddress, OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_RESTAKEDLSETHVAULT);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.restakedLsETHVault.delegator, operators.operator1PierTwo.evmAddress, OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.restakedLsETHVault.delegator,
            operators.operator3Nodeinfra.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.restakedLsETHVault.delegator,
            operators.operator4Blockscape.evmAddress,
            OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_OPSLAYER);
        _setSharesIfNeeded(
            vaultsAddressesDeployedA.opslayer.delegator, operators.operator11Opslayer.evmAddress, OPERATOR_SHARE
        );

        vm.startPrank(VAULT_MANAGER_GAUNTLET);
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator,
            operators.operator10Alchemy.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
            operators.operator10Alchemy.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedRETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
            operators.operator10Alchemy.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
            operators.operator10Alchemy.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator,
            operators.operator10Alchemy.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator,
            operators.operator1PierTwo.evmAddress,
            OPERATOR_SHARE
        );
        _setSharesIfNeeded(
            vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator, operators.operator2P2P.evmAddress, OPERATOR_SHARE
        );

        vm.stopPrank();
    }

    function _setSharesIfNeeded(address _delegator, address _operator, uint256 _shares) private {
        INetworkRestakeDelegator delegator = INetworkRestakeDelegator(_delegator);
        if (delegator.operatorNetworkShares(tanssi.subnetwork(0), _operator) == 0) {
            console2.log("Setting shares for", _delegator, _operator);
            delegator.setOperatorNetworkShares(tanssi.subnetwork(0), _operator, _shares);
        }
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
        vm.prank(admin);
        ecosystemEntities.middleware.setGateway(address(gateway));
    }

    function _saveStakeBeforeDepositing() private {
        vaultStakeBeforeDepositA.mevRestakedETH = IVault(vaultsAddressesDeployedA.mevRestakedETH.vault).activeStake();
        vaultStakeBeforeDepositA.mevCapitalETH = IVault(vaultsAddressesDeployedA.mevCapitalETH.vault).activeStake();
        vaultStakeBeforeDepositA.hashKeyCloudETH = IVault(vaultsAddressesDeployedA.hashKeyCloudETH.vault).activeStake();
        vaultStakeBeforeDepositA.renzoRestakedETH =
            IVault(vaultsAddressesDeployedA.renzoRestakedETH.vault).activeStake();
        vaultStakeBeforeDepositA.re7LabsETH = IVault(vaultsAddressesDeployedA.re7LabsETH.vault).activeStake();
        vaultStakeBeforeDepositA.re7LabsRestakingETH =
            IVault(vaultsAddressesDeployedA.re7LabsRestakingETH.vault).activeStake();
        vaultStakeBeforeDepositA.cp0xLrtETH = IVault(vaultsAddressesDeployedA.cp0xLrtETH.vault).activeStake();
        vaultStakeBeforeDepositB.gauntletRestakedWstETH =
            IVault(vaultsAddressesDeployedB.gauntletRestakedWstETH.vault).activeStake();
        vaultStakeBeforeDepositB.gauntletRestakedSwETH =
            IVault(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault).activeStake();
        vaultStakeBeforeDepositB.gauntletRestakedRETH =
            IVault(vaultsAddressesDeployedB.gauntletRestakedRETH.vault).activeStake();

        vaultStakeBeforeDepositB.gauntletRestakedWBETH =
            IVault(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault).activeStake();
        vaultStakeBeforeDepositB.gauntletRestakedcBETH =
            IVault(vaultsAddressesDeployedB.gauntletRestakedcBETH.vault).activeStake();
        vaultStakeBeforeDepositA.etherfiwstETH = IVault(vaultsAddressesDeployedA.etherfiwstETH.vault).activeStake();
        vaultStakeBeforeDepositA.restakedLsETHVault =
            IVault(vaultsAddressesDeployedA.restakedLsETHVault.vault).activeStake();
    }

    function _getMaximumAvailableStakeForVault(
        address delegator,
        uint256 vaultActiveStake
    ) private view returns (uint256 maximumAvailableStake) {
        maximumAvailableStake =
            Math.min(INetworkRestakeDelegator(delegator).networkLimit(tanssi.subnetwork(0)), vaultActiveStake);
    }

    // function _calculateOperatorPower1() private view returns (uint256 operatorPower1) {
    //     operatorPower1 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.mevRestakedETH.delegator,
    //                 vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_RESTAKED
    //             ),
    //             TOTAL_SHARES_MEV_RESTAKED
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.mevCapitalETH.delegator,
    //                     vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //                 ),
    //                 TOTAL_SHARES_MEV_CAPITAL
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.hashKeyCloudETH.delegator,
    //                     vaultStakeBeforeDeposit.hashKeyCloudStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_HASH_KEY_CLOUD
    //                 ),
    //                 TOTAL_SHARES_HASH_KEY_CLOUD
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower2() private view returns (uint256 operatorPower2) {
    //     operatorPower2 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.mevCapitalETH.delegator,
    //                 vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //             ),
    //             TOTAL_SHARES_MEV_CAPITAL
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower3() private view returns (uint256 operatorPower3) {
    //     operatorPower3 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.re7LabsRestakingETH.delegator,
    //                 vaultStakeBeforeDeposit.gauntletRestakedCbStakeBeforeDeposit
    //                     + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
    //             ),
    //             TOTAL_SHARES_RE7_LABS_RESTAKING
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower4() private view returns (uint256 operatorPower4) {
    //     operatorPower4 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
    //                 vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
    //                     + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //             ),
    //             TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //         )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower5() private view returns (uint256 operatorPower5) {
    //     operatorPower5 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                 vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit + OPERATOR_STAKE * 2
    //             ),
    //             TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //         )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower6() private view returns (uint256 operatorPower6) {
    //     operatorPower6 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.mevRestakedETH.delegator,
    //                 vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //             ),
    //             TOTAL_SHARES_MEV_RESTAKED
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.mevCapitalETH.delegator,
    //                     vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //                 ),
    //                 TOTAL_SHARES_MEV_CAPITAL
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.cp0xLrtETH.delegator,
    //                     vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
    //                 ),
    //                 TOTAL_SHARES_CP0X_LRT
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower7() private view returns (uint256 operatorPower7) {
    //     operatorPower7 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.renzoRestakedETH.delegator,
    //                 vaultStakeBeforeDeposit.renzoRestakedStakeBeforeDeposit
    //                     + OPERATOR_STAKE * TOTAL_SHARES_RENZO_RESTAKED
    //             ),
    //             TOTAL_SHARES_RENZO_RESTAKED
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.re7LabsRestakingETH.delegator,
    //                     vaultStakeBeforeDeposit.re7LabsRestakingStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
    //                 ),
    //                 TOTAL_SHARES_RE7_LABS_RESTAKING
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower8() private view returns (uint256 operatorPower8) {
    //     operatorPower8 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator,
    //                 vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
    //                     + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //             ),
    //             TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower9() private view returns (uint256 operatorPower9) {
    //     operatorPower9 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.cp0xLrtETH.delegator,
    //                 vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
    //             ),
    //             TOTAL_SHARES_CP0X_LRT
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    // function _calculateOperatorPower10() private view returns (uint256 operatorPower10) {
    //     operatorPower10 = (
    //         OPERATOR_SHARE.mulDiv(
    //             _getMaximumAvailableStakeForVault(
    //                 vaultsAddressesDeployedA.mevRestakedETH.delegator,
    //                 vaultStakeBeforeDeposit.mevRestakedStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //             ),
    //             TOTAL_SHARES_MEV_RESTAKED
    //         )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.mevCapitalETH.delegator,
    //                     vaultStakeBeforeDeposit.mevCapitalStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_MEV_CAPITAL
    //                 ),
    //                 TOTAL_SHARES_MEV_CAPITAL
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.hashKeyCloudETH.delegator,
    //                     vaultStakeBeforeDeposit.hashKeyCloudStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_HASH_KEY_CLOUD
    //                 ),
    //                 TOTAL_SHARES_HASH_KEY_CLOUD
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.cp0xLrtETH.delegator,
    //                     vaultStakeBeforeDeposit.cp0xLrtStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_CP0X_LRT
    //                 ),
    //                 TOTAL_SHARES_CP0X_LRT
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.re7LabsRestakingETH.delegator,
    //                     vaultStakeBeforeDeposit.re7LabsRestakingStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS_RESTAKING
    //                 ),
    //                 TOTAL_SHARES_RE7_LABS_RESTAKING
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.renzoRestakedETH.delegator,
    //                     vaultStakeBeforeDeposit.renzoRestakedStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_RENZO_RESTAKED
    //                 ),
    //                 TOTAL_SHARES_RENZO_RESTAKED
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedA.re7LabsETH.delegator,
    //                     vaultStakeBeforeDeposit.re7LabsStakeBeforeDeposit + OPERATOR_STAKE * TOTAL_SHARES_RE7_LABS
    //                 ),
    //                 TOTAL_SHARES_RE7_LABS
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWstStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WSTETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedRETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedRETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_RETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedWBETHStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_WBETH
    //             )
    //             + OPERATOR_SHARE.mulDiv(
    //                 _getMaximumAvailableStakeForVault(
    //                     vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator,
    //                     vaultStakeBeforeDeposit.gauntletRestakedSwStakeBeforeDeposit
    //                         + OPERATOR_STAKE * TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //                 ),
    //                 TOTAL_SHARES_GAUNTLET_RESTAKED_SWETH
    //             )
    //     ).mulDiv(uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS);
    // }

    function _checkOperatorVaultPairs(
        Middleware.OperatorVaultPair[] memory operatorVaultPairs,
        address operator,
        uint256 totalVaults
    ) private pure {
        bool found;
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            if (operatorVaultPairs[i].operator == operator) {
                found = true;
                assertEq(operatorVaultPairs[i].vaults.length, totalVaults);
            }
        }
        assertEq(found, true, "Operator not found");
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
        vm.warp(block.timestamp + 7 days + 1); // In 7 days there should be a new vault epoch in all epochs
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(currentEpoch);

        address[] memory activeOperators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).activeOperators();

        console2.log("Active operators", activeOperators.length);
        console2.log("Total operators", operatorVaultPairs.length);
        // for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
        //     console2.log("Operator", operatorVaultPairs[i].operator);
        //     console2.log("Vaults", operatorVaultPairs[i].vaults.length);
        // }

        uint256 epochStartTs = ecosystemEntities.middleware.getEpochStart(currentEpoch);

        address[] memory vaults =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).activeVaultsAt(uint48(epochStartTs));
        console2.log("Vaults", vaults.length);
        uint256 totalVaults;
        (totalVaults, vaults) = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaults(
            operators.operator5QuantNode.evmAddress, uint48(epochStartTs)
        );
        console2.log("Total vaults operators.operator5QuantNode.evmAddress", totalVaults);

        (totalVaults, vaults) = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaults(
            operators.operator6NodeMonster.evmAddress, uint48(epochStartTs)
        );
        console2.log("Total vaults operators.operator6NodeMonster.evmAddress", totalVaults);

        (totalVaults, vaults) = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaults(
            operators.operator7BlockBones.evmAddress, uint48(epochStartTs)
        );
        console2.log("Total vaults operators.operator7BlockBones.evmAddress", totalVaults);

        uint256 stake = IBaseDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).stakeAt(
            tanssi.subnetwork(0), operators.operator5QuantNode.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Stake operators.operator5QuantNode.evmAddress", stake);

        stake = IBaseDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).stakeAt(
            tanssi.subnetwork(0), operators.operator6NodeMonster.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Stake operators.operator6NodeMonster.evmAddress", stake);

        stake = IBaseDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).stakeAt(
            tanssi.subnetwork(0), operators.operator7BlockBones.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Stake operators.operator7BlockBones.evmAddress", stake);

        stake = IVault(vaultsAddressesDeployedA.re7LabsETH.vault).activeStakeAt(uint48(epochStartTs), new bytes(0));
        console2.log("Stake re7LabsETH", stake);
        uint256 networkLimit = INetworkRestakeDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).networkLimitAt(
            tanssi.subnetwork(0), uint48(epochStartTs), new bytes(0)
        );
        console2.log("Network limit re7LabsETH", networkLimit);

        uint256 networkShares = INetworkRestakeDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator)
            .totalOperatorNetworkShares(tanssi.subnetwork(0));
        console2.log("Network shares re7LabsETH", networkShares);

        networkShares = INetworkRestakeDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).operatorNetworkSharesAt(
            tanssi.subnetwork(0), operators.operator5QuantNode.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Network shares operators.operator5QuantNode.evmAddress", networkShares);
        networkShares = INetworkRestakeDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).operatorNetworkSharesAt(
            tanssi.subnetwork(0), operators.operator6NodeMonster.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Network shares operators.operator6NodeMonster.evmAddress", networkShares);
        networkShares = INetworkRestakeDelegator(vaultsAddressesDeployedA.re7LabsETH.delegator).operatorNetworkSharesAt(
            tanssi.subnetwork(0), operators.operator7BlockBones.evmAddress, uint48(epochStartTs), new bytes(0)
        );
        console2.log("Network shares operators.operator7BlockBones.evmAddress", networkShares);

        assertEq(operatorVaultPairs.length, TOTAL_OPERATORS);

        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator1PierTwo.evmAddress, PIER_TWO_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator2P2P.evmAddress, P2P_VAULTS);
        _checkOperatorVaultPairs(
            operatorVaultPairs, operators.operator8CP0XStakrspace.evmAddress, CP0X_STAKRSPACE_VAULTS
        );
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator3Nodeinfra.evmAddress, NODE_INFRA);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator4Blockscape.evmAddress, BLOCKSCAPE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator5QuantNode.evmAddress, QUANT_NODE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator6NodeMonster.evmAddress, NODE_MONSTER_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator7BlockBones.evmAddress, BLOCK_BONES_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator9HashkeyCloud.evmAddress, HASHKEY_CLOUD_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator10Alchemy.evmAddress, ALCHEMY_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator11Opslayer.evmAddress, OPSLAYER_VAULTS);
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

    // function testWithdrawForOperator1() public {
    //     IVault vaultMevRestaked = IVault(vaultsAddressesDeployedA.mevRestakedETH.vault);
    //     IVault vaultMevCapital = IVault(vaultsAddressesDeployedA.mevCapitalETH.vault);
    //     IVault vaultHashkeyCloud = IVault(vaultsAddressesDeployedA.hashKeyCloudETH.vault);
    //     uint256 currentEpochMevRestaked = vaultMevRestaked.currentEpoch();
    //     uint256 currentEpochMevCapital = vaultMevCapital.currentEpoch();
    //     uint256 currentEpochHashkeyCloud = vaultHashkeyCloud.currentEpoch();

    //     uint256 currentEpochMevRestakedEpochDuration = vaultMevRestaked.epochDuration();
    //     uint256 currentEpochMevCapitalEpochDuration = vaultMevCapital.epochDuration();
    //     uint256 currentEpochHashkeyCloudEpochDuration = vaultHashkeyCloud.epochDuration();

    //     uint256 currentTimestamp = block.timestamp;

    //     vm.startPrank(operator);
    //     vaultMevRestaked.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);
    //     vaultMevCapital.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);
    //     vaultHashkeyCloud.withdraw(operator, DEFAULT_WITHDRAW_AMOUNT);

    //     vm.warp(currentTimestamp + currentEpochMevRestakedEpochDuration * 2 + 1);
    //     currentEpochMevRestaked = vaultMevRestaked.currentEpoch();
    //     vaultMevRestaked.claim(operator, currentEpochMevRestaked - 1);

    //     vm.warp(currentTimestamp + currentEpochMevCapitalEpochDuration * 2 + 1);
    //     currentEpochMevCapital = vaultMevCapital.currentEpoch();
    //     vaultMevCapital.claim(operator, currentEpochMevCapital - 1);

    //     vm.warp(currentTimestamp + currentEpochHashkeyCloudEpochDuration * 2 + 1);
    //     currentEpochHashkeyCloud = vaultHashkeyCloud.currentEpoch();
    //     vaultHashkeyCloud.claim(operator, currentEpochHashkeyCloud - 1);

    //     assertEq(
    //         ecosystemEntities.wstETH.balanceOf(operator),
    //         OPERATOR_INITIAL_BALANCE * 4 - OPERATOR_STAKE * 3 + DEFAULT_WITHDRAW_AMOUNT * 3
    //     );
    // }

    // function testWithdrawForOperator2() public {
    //     IVault vaultMevCapital = IVault(vaultsAddressesDeployedA.mevCapitalETH.vault);
    //     IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployedB.gauntletRestakedRETH.vault);
    //     IVault vaultGauntletRestakedWBETH = IVault(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault);

    //     uint256 currentEpochMevCapital = vaultMevCapital.currentEpoch();
    //     uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     uint256 currentEpochGauntletRestakedWBETH = vaultGauntletRestakedWBETH.currentEpoch();

    //     uint256 currentEpochMevCapitalEpochDuration = vaultMevCapital.epochDuration();
    //     uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();
    //     uint256 currentEpochGauntletRestakedWBETHEpochDuration = vaultGauntletRestakedWBETH.epochDuration();

    //     uint256 currentTimestamp = block.timestamp;

    //     vm.startPrank(operator2);
    //     vaultMevCapital.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);
    //     vaultGauntletRestaked.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);
    //     vaultGauntletRestakedWBETH.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);

    //     vm.warp(currentTimestamp + currentEpochMevCapitalEpochDuration * 2 + 1);
    //     currentEpochMevCapital = vaultMevCapital.currentEpoch();
    //     vaultMevCapital.claim(operator2, currentEpochMevCapital - 1);

    //     vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
    //     currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     vaultGauntletRestaked.claim(operator2, currentEpochGauntletRestaked - 1);

    //     vm.warp(currentTimestamp + currentEpochGauntletRestakedWBETHEpochDuration * 2 + 1);
    //     currentEpochGauntletRestakedWBETH = vaultGauntletRestakedWBETH.currentEpoch();
    //     vaultGauntletRestakedWBETH.claim(operator2, currentEpochGauntletRestakedWBETH - 1);

    //     assertEq(
    //         ecosystemEntities.wstETH.balanceOf(operator2),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    //     assertEq(
    //         ecosystemEntities.rETH.balanceOf(operator2),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    //     assertEq(
    //         ecosystemEntities.wBETH.balanceOf(operator2),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    // }

    // function testWithdrawForOperator3() public {
    //     IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployedB.gauntletRestakedRETH.vault);
    //     IVault vaultRe7LabsRestaked = IVault(vaultsAddressesDeployedA.re7LabsRestakingETH.vault);

    //     uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     uint256 currentEpochRe7LabsRestaked = vaultRe7LabsRestaked.currentEpoch();

    //     uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();
    //     uint256 currentEpochRe7LabsRestakedEpochDuration = vaultRe7LabsRestaked.epochDuration();

    //     uint256 currentTimestamp = block.timestamp;

    //     vm.startPrank(operator3);
    //     vaultGauntletRestaked.withdraw(operator3, DEFAULT_WITHDRAW_AMOUNT);
    //     vaultRe7LabsRestaked.withdraw(operator3, DEFAULT_WITHDRAW_AMOUNT);

    //     vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
    //     currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     vaultGauntletRestaked.claim(operator3, currentEpochGauntletRestaked - 1);

    //     vm.warp(currentTimestamp + currentEpochRe7LabsRestakedEpochDuration * 2 + 1);
    //     currentEpochRe7LabsRestakedEpochDuration = vaultRe7LabsRestaked.currentEpoch();
    //     vaultRe7LabsRestaked.claim(operator3, currentEpochRe7LabsRestakedEpochDuration - 1);

    //     assertEq(
    //         ecosystemEntities.rETH.balanceOf(operator3),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    //     assertEq(
    //         ecosystemEntities.wstETH.balanceOf(operator3),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    // }

    // function testWithdrawForOperator4() public {
    //     IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault);

    //     uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();

    //     uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();

    //     uint256 currentTimestamp = block.timestamp;

    //     vm.startPrank(operator4);
    //     vaultGauntletRestaked.withdraw(operator4, DEFAULT_WITHDRAW_AMOUNT);

    //     vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
    //     currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     vaultGauntletRestaked.claim(operator4, currentEpochGauntletRestaked - 1);

    //     assertEq(
    //         ecosystemEntities.swETH.balanceOf(operator4),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    // }

    // function testWithdrawForOperator5() public {
    //     IVault vaultGauntletRestaked = IVault(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault);

    //     uint256 currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();

    //     uint256 currentEpochGauntletRestakedEpochDuration = vaultGauntletRestaked.epochDuration();

    //     uint256 currentTimestamp = block.timestamp;

    //     vm.startPrank(operator5);
    //     vaultGauntletRestaked.withdraw(operator5, DEFAULT_WITHDRAW_AMOUNT);

    //     vm.warp(currentTimestamp + currentEpochGauntletRestakedEpochDuration * 2 + 1);
    //     currentEpochGauntletRestaked = vaultGauntletRestaked.currentEpoch();
    //     vaultGauntletRestaked.claim(operator5, currentEpochGauntletRestaked - 1);

    //     assertEq(
    //         ecosystemEntities.wBETH.balanceOf(operator5),
    //         OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT
    //     );
    // }

    // function testOperatorPower() public {
    //     vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
    //     uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
    //     Middleware.ValidatorData[] memory validators =
    //         OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);

    //     uint256 operatorPower1 = _calculateOperatorPower1();
    //     uint256 operatorPower2 = _calculateOperatorPower2();
    //     uint256 operatorPower3 = _calculateOperatorPower3();
    //     uint256 operatorPower4 = _calculateOperatorPower4();
    //     uint256 operatorPower5 = _calculateOperatorPower5();

    //     assertEq(validators[0].power, operatorPower1);
    //     assertEq(validators[1].power, operatorPower2);
    //     assertEq(validators[2].power, operatorPower3);
    //     assertEq(validators[3].power, operatorPower4);
    //     assertEq(validators[4].power, operatorPower5);
    // }

    function testPauseAndUnregisterOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        vm.startPrank(admin);
        ecosystemEntities.middleware.pauseOperator(operators.operator1PierTwo.evmAddress);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);

        ecosystemEntities.middleware.unregisterOperator(operators.operator1PierTwo.evmAddress);
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS - 1); // One less operator

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        ecosystemEntities.middleware.registerOperator(
            operators.operator1PierTwo.evmAddress, abi.encode(bytes32(uint256(12))), address(0)
        );

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS); // One more operator
    }

    function testPauseAndUnpausingOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);

        vm.startPrank(admin);
        ecosystemEntities.middleware.pauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS - 1); // One less operator

        ecosystemEntities.middleware.unpauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS);
    }

    function testUpkeep() public {
        vm.prank(admin);
        ecosystemEntities.middleware.setForwarder(forwarder);
        // It's not needed (anyone can call it), it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        vm.prank(offlineKeepers);
        uint256 beforeGas = gasleft();
        (bool upkeepNeeded, bytes memory performData) = ecosystemEntities.middleware.checkUpkeep(hex"");
        uint256 afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, 10 ** 7); // Check that gas is lower than 10M

        bytes32[] memory sortedKeys = abi.decode(performData, (bytes32[]));
        assertEq(sortedKeys.length, TOTAL_OPERATORS);

        vm.prank(forwarder);
        beforeGas = gasleft();
        vm.expectEmit(true, false, false, false);
        emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
        ecosystemEntities.middleware.performUpkeep(performData);
        afterGas = gasleft();
        assertLt(beforeGas - afterGas, 10 ** 7); // Check that gas is lower than 10M

        (upkeepNeeded,) = ecosystemEntities.middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);
    }

    function testMiddlewareIsUpgradeable() public {
        address operatorRewardsAddress = makeAddr("operatorRewards");
        address stakerRewardsFactoryAddress = makeAddr("stakerRewardsFactory");
        Middleware middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);

        vm.startPrank(admin);
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
    //     _optInOperator(operator4, address(ecosystemEntities.vault), network2);

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
