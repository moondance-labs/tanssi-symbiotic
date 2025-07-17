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
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {IDefaultStakerRewards} from "@symbiotic-rewards/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

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

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************

import {DIAOracleMock} from "test/mocks/DIAOracleMock.sol";
import {AggregatorV3Proxy} from "src/contracts/oracle-proxy/AggregatorV3Proxy.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {ODefaultStakerRewardsFactory} from "src/contracts/rewarder/ODefaultStakerRewardsFactory.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {MiddlewareV2} from "test/unit/utils/MiddlewareV2.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {Token} from "test/mocks/Token.sol";

contract FullTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 2 days;
    uint48 public constant VETO_DURATION = 3 days;
    uint256 public constant SLASH_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_STAKE = 90 ether;
    uint256 public constant DEFAULT_WITHDRAW_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    uint256 public constant MIN_DEPOSIT = 10 ether; // 10 ETH
    uint256 public constant TOKEN_REWARDS_PER_ERA_INDEX = 10_000 * 10 ** 12; // Tanssi has 12 decimals.

    uint256 public constant OPERATOR_SHARE = 2000; // 20%
    uint256 public constant MAX_PERCENTAGE = 10_000;
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
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 20; // 5%
    uint8 public constant ORACLE_DECIMALS = 2;
    int256 public constant ORACLE_CONVERSION_TOKEN = 2000;

    uint256 TANSSI_VAULT_DEPOSIT_AMOUNT = 500_000 * 10 ** 12; // 500k TANSSI
    uint8 public constant TANSSI_ORACLE_DECIMALS = 8;
    int256 public constant TANSSI_ORACLE_CONVERSION_TOKEN = int256(1 * 10 ** TANSSI_ORACLE_DECIMALS); // 1 USD

    uint256 public constant MAX_CHAINLINK_PROCESSABLE_BYTES = 2000;
    uint256 public constant MAX_CHAINLINK_CHECKUPKEEP_GAS = 10 ** 7; // 10M gas
    uint256 public constant MAX_CHAINLINK_PERFORMUPKEEP_GAS = 5 * 10 ** 6; // 5M gas

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

    uint256 public constant MAX_ADMIN_FEE_BPS = 100; // 1%
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

    address public constant WHITELIST_SETTER_ETHERFIWSTETH = 0x2aCA71020De61bb532008049e1Bd41E451aE8AdC;
    address public constant WHITELIST_SETTER_MEVCAPITAL = 0x8989e3f949df80e8eFcbf3372F082699b93E5C09;

    bytes32 public constant DEPOSIT_WHITELIST_SET_ROLE = keccak256("DEPOSIT_WHITELIST_SET_ROLE");

    address public forwarder = makeAddr("forwarder");

    HelperConfig helperConfig;
    string public json;

    address public admin;
    address public tanssi;
    address stakerRewardsImpl;

    GatewayProxy gateway;
    Middleware middleware;
    OBaseMiddlewareReader reader;
    ODefaultOperatorRewards operatorRewards;
    Token rewardsToken;
    HelperConfig.TokensConfig public tokensConfig;
    HelperConfig.OperatorConfig public operators;
    ProofAndPointsByOperator public proofAndPointsByOperator;

    HelperConfig.VaultsConfigA public vaultsAddressesDeployedA;
    HelperConfig.VaultsConfigB public vaultsAddressesDeployedB;

    TotalSharesA public totalSharesA;
    TotalSharesB public totalSharesB;

    NetworkLimitsA public networkLimitsA;
    NetworkLimitsB public networkLimitsB;

    mapping(address vault => address stakerRewards) vaultToStakerRewards;

    struct TotalSharesA {
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

    struct TotalSharesB {
        uint256 gauntletRestakedWstETH;
        uint256 gauntletRestakedSwETH;
        uint256 gauntletRestakedRETH;
        uint256 gauntletRestakedWBETH;
        uint256 gauntletRestakedcBETH;
    }

    struct NetworkLimitsA {
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

    struct NetworkLimitsB {
        uint256 gauntletRestakedWstETH;
        uint256 gauntletRestakedSwETH;
        uint256 gauntletRestakedRETH;
        uint256 gauntletRestakedWBETH;
        uint256 gauntletRestakedcBETH;
    }

    struct ProofAndPoints {
        bytes32[] proof;
        uint32 points;
    }

    struct ProofAndPointsByOperator {
        ProofAndPoints operator1PierTwo;
        ProofAndPoints operator2P2P;
        ProofAndPoints operator3Nodeinfra;
        ProofAndPoints operator4Blockscape;
        ProofAndPoints operator5QuantNode;
        ProofAndPoints operator6NodeMonster;
        ProofAndPoints operator7BlockBones;
        ProofAndPoints operator8CP0XStakrspace;
        ProofAndPoints operator9HashkeyCloud;
        ProofAndPoints operator10Alchemy;
        ProofAndPoints operator11Opslayer;
    }

    function setUp() public {
        string memory project_root = vm.projectRoot();
        string memory path = string.concat(project_root, "/test/fork/mainnet/rewards_data.json");
        json = vm.readFile(path);

        _getBaseInfrastructure();
        _cacheAllVaultToStakerRewards();
        _setLimitsAndShares();
        _setupOperators();
        _registerEntitiesToMiddleware();

        _saveTotalShares();

        /// middleware.setCollateralToOracle(xxx, oracle); Already added for each collateral: wstETH, rETH, swETH, wBETH, LsETH, cbETH
        vm.stopPrank();

        vm.warp(block.timestamp + 14 days + 1); // In 14 days there should be a new vault epoch in all vaults

        _saveAllOperatorPowers();
    }

    function _getBaseInfrastructure() private {
        // Check if it's good for mainnet
        helperConfig = new HelperConfig();
        HelperConfig.Entities memory entities;
        HelperConfig.NetworkConfig memory networkConfig;
        (entities, networkConfig, tokensConfig, vaultsAddressesDeployedA, vaultsAddressesDeployedB, operators) =
            helperConfig.getChainConfig();

        admin = entities.admin;
        tanssi = entities.tanssi;
        gateway = GatewayProxy(payable(entities.gateway));
        middleware = Middleware(entities.middleware);
        reader = OBaseMiddlewareReader(address(middleware));
        operatorRewards = ODefaultOperatorRewards(entities.operatorRewards);
        rewardsToken = Token(entities.rewardsToken);

        // For now we need this as we can't use the one already deployed
        stakerRewardsImpl = address(new ODefaultStakerRewards(networkConfig.networkMiddlewareService, entities.tanssi));
    }

    function _cacheAllVaultToStakerRewards() private {
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.mevRestakedETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.mevCapitalETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.hashKeyCloudETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.renzoRestakedETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.re7LabsETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.re7LabsRestakingETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.cp0xLrtETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.etherfiwstETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.restakedLsETHVault);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedA.opslayer);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.gauntletRestakedWstETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.gauntletRestakedSwETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.gauntletRestakedRETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.gauntletRestakedWBETH);
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.gauntletRestakedcBETH);
    }

    function _cacheVaultToStakerRewards(
        HelperConfig.VaultData memory vaultData
    ) private {
        vaultToStakerRewards[vaultData.vault] = vaultData.stakerRewards;
    }

    function _setupOperators() private {
        // OPERATOR 1 - Pier Two
        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.etherfiwstETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedA.etherfiwstETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedB.gauntletRestakedcBETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedB.gauntletRestakedRETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWstETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedA.mevRestakedETH.vault);

        _optInOperator(operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.renzoRestakedETH, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedA.renzoRestakedETH.vault);

        _optInOperator(
            operators.operator1PierTwo.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );
        operators.operator1PierTwo.vaults.push(vaultsAddressesDeployedA.restakedLsETHVault.vault);

        // OPERATOR 2 - P2P
        _optInOperator(operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.etherfiwstETH, tanssi, address(0));
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedA.etherfiwstETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedB.gauntletRestakedcBETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedB.gauntletRestakedRETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWstETH.vault);

        _optInOperator(operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        _optInOperator(
            operators.operator2P2P.evmAddress, vaultsAddressesDeployedA.re7LabsRestakingETH, tanssi, address(0)
        );
        operators.operator2P2P.vaults.push(vaultsAddressesDeployedA.re7LabsRestakingETH.vault);

        // OPERATOR 3 - Nodeinfra
        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );
        operators.operator3Nodeinfra.vaults.push(vaultsAddressesDeployedA.mevRestakedETH.vault);

        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );
        operators.operator3Nodeinfra.vaults.push(vaultsAddressesDeployedA.mevCapitalETH.vault);

        _optInOperator(
            operators.operator3Nodeinfra.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );
        operators.operator3Nodeinfra.vaults.push(vaultsAddressesDeployedA.restakedLsETHVault.vault);

        // OPERATOR 4 - Blockscape
        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );
        operators.operator4Blockscape.vaults.push(vaultsAddressesDeployedA.mevRestakedETH.vault);

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );
        operators.operator4Blockscape.vaults.push(vaultsAddressesDeployedA.mevCapitalETH.vault);

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );
        operators.operator4Blockscape.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        _optInOperator(
            operators.operator4Blockscape.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );
        operators.operator4Blockscape.vaults.push(vaultsAddressesDeployedA.restakedLsETHVault.vault);

        // OPERATOR 5 - Quant Node
        _optInOperator(operators.operator5QuantNode.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0));
        operators.operator5QuantNode.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        // OPERATOR 6 - Node Monster
        _optInOperator(
            operators.operator6NodeMonster.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );
        operators.operator6NodeMonster.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        // OPERATOR 7 - BlocknBones
        _optInOperator(
            operators.operator7BlockBones.evmAddress, vaultsAddressesDeployedA.re7LabsETH, tanssi, address(0)
        );
        operators.operator7BlockBones.vaults.push(vaultsAddressesDeployedA.re7LabsETH.vault);

        // OPERATOR 8 - CP0X Stakrspace
        _optInOperator(
            operators.operator8CP0XStakrspace.evmAddress, vaultsAddressesDeployedA.cp0xLrtETH, tanssi, address(0)
        );
        operators.operator8CP0XStakrspace.vaults.push(vaultsAddressesDeployedA.cp0xLrtETH.vault);

        _optInOperator(
            operators.operator8CP0XStakrspace.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );
        operators.operator8CP0XStakrspace.vaults.push(vaultsAddressesDeployedA.mevCapitalETH.vault);

        // OPERATOR 9 - Hashkey Cloud
        _optInOperator(
            operators.operator9HashkeyCloud.evmAddress, vaultsAddressesDeployedA.hashKeyCloudETH, tanssi, address(0)
        );
        operators.operator9HashkeyCloud.vaults.push(vaultsAddressesDeployedA.hashKeyCloudETH.vault);

        // OPERATOR 10 - Alchemy
        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.mevRestakedETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedA.mevRestakedETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.mevCapitalETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedA.mevCapitalETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedA.restakedLsETHVault, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedA.restakedLsETHVault.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWstETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWstETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedSwETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedRETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedB.gauntletRestakedRETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedWBETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault);

        _optInOperator(
            operators.operator10Alchemy.evmAddress, vaultsAddressesDeployedB.gauntletRestakedcBETH, tanssi, address(0)
        );
        operators.operator10Alchemy.vaults.push(vaultsAddressesDeployedB.gauntletRestakedcBETH.vault);

        // OPERATOR 11 - Ops Layer
        _optInOperator(
            operators.operator11Opslayer.evmAddress, vaultsAddressesDeployedA.opslayer, tanssi, VAULT_MANAGER_OPSLAYER
        );
        operators.operator11Opslayer.vaults.push(vaultsAddressesDeployedA.opslayer.vault);
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
            adminFeeSetRoleHolder: admin,
            implementation: stakerRewardsImpl
        });

        vm.startPrank(admin);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.mevRestakedETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.mevCapitalETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.hashKeyCloudETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.renzoRestakedETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.re7LabsETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.re7LabsRestakingETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.cp0xLrtETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.etherfiwstETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.restakedLsETHVault.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedA.opslayer.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedB.gauntletRestakedWstETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedB.gauntletRestakedWBETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedB.gauntletRestakedSwETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedB.gauntletRestakedRETH.vault, stakerRewardsParams);

        _registerVaultIfNotActive(vaultsAddressesDeployedB.gauntletRestakedcBETH.vault, stakerRewardsParams);

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
        if (!reader.isOperatorRegistered(operator.evmAddress)) {
            console2.log("Registering operator", operator.evmAddress);
            middleware.registerOperator(operator.evmAddress, abi.encode(operator.operatorKey), address(0));
        }
    }

    function _registerVaultIfNotActive(
        address _vault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) private {
        if (!reader.isVaultRegistered(_vault)) {
            console2.log("Registering vault", _vault);
            middleware.registerSharedVault(_vault, stakerRewardsParams);
        }
    }

    function _optInOperator(
        address operator,
        HelperConfig.VaultData memory vaultData,
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
        IVault vault = IVault(vaultData.vault);

        {
            if (vault.depositWhitelist()) {
                if (vaultManager != address(0)) {
                    vm.startPrank(vaultManager);
                    vault.setDepositorWhitelistStatus(operator, true);
                }
                // This is the vault manager for several vaults.
                else if (IAccessControl(vaultData.vault).hasRole(DEPOSIT_WHITELIST_SET_ROLE, vaultManager)) {
                    vm.startPrank(VAULT_MANAGER_COMMON);
                    IVault(vaultData.vault).setDepositorWhitelistStatus(operator, true);
                }
            }
        }

        vm.startPrank(operator);
        if (!operatorRegistry.isEntity(operator)) {
            console2.log("Registering operator", operator);
            operatorRegistry.registerOperator();
        }

        if (!operatorVaultOptInService.isOptedIn(operator, vaultData.vault)) {
            console2.log("Opting in operator", operator, "to vault", vaultData.vault);
            operatorVaultOptInService.optIn(vaultData.vault);
        }

        uint256 operatorStake = IBaseDelegator(vaultData.delegator).stakeAt(
            tanssi.subnetwork(0), operator, uint48(block.timestamp), new bytes(0)
        );
        if (operatorStake == 0) {
            console2.log("Operator", operator, "has no stake into vault", vaultData.vault);
        }
        uint256 activeBalanceOf = vault.activeBalanceOf(operator);
        if (activeBalanceOf == 0) {
            console2.log("Operator", operator, "has no deposit into vault", vaultData.vault);
        }

        if (!operatorNetworkOptInService.isOptedIn(operator, network)) {
            console2.log("Opting in operator", operator, "to network", network);
            operatorNetworkOptInService.optIn(network);
        }

        vm.stopPrank();
    }

    function _setLimitsAndShares() private {
        _setMaxNetworkLimits();
        _setNetworkLimits();
        _setOperatorShares();
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
        networkLimitsA.mevRestakedETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_MEVRESTAKEDETH, vaultsAddressesDeployedA.mevRestakedETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.mevCapitalETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_MEVCAPITALETH, vaultsAddressesDeployedA.mevCapitalETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.hashKeyCloudETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_HASHKEYCLOUDETH, vaultsAddressesDeployedA.hashKeyCloudETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.renzoRestakedETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RENZORESTAKEDETH, vaultsAddressesDeployedA.renzoRestakedETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.re7LabsETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RE7LABS, vaultsAddressesDeployedA.re7LabsETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.re7LabsRestakingETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RE7LABS, vaultsAddressesDeployedA.re7LabsRestakingETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.cp0xLrtETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_ETHERFIWSTETH, vaultsAddressesDeployedA.etherfiwstETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.etherfiwstETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_RESTAKEDLSETHVAULT,
            vaultsAddressesDeployedA.restakedLsETHVault.delegator,
            OPERATOR_NETWORK_LIMIT
        );

        networkLimitsA.opslayer = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_OPSLAYER, vaultsAddressesDeployedA.opslayer.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsB.gauntletRestakedcBETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsB.gauntletRestakedRETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedRETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsB.gauntletRestakedSwETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsB.gauntletRestakedWBETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator, OPERATOR_NETWORK_LIMIT
        );

        networkLimitsB.gauntletRestakedWstETH = _setNetworkLimitIfNeeded(
            VAULT_MANAGER_GAUNTLET, vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator, OPERATOR_NETWORK_LIMIT
        );
    }

    function _setNetworkLimitIfNeeded(
        address manager,
        address _delegator,
        uint256 _limit
    ) private returns (uint256 networkLimit) {
        vm.startPrank(manager);
        INetworkRestakeDelegator delegator = INetworkRestakeDelegator(_delegator);

        networkLimit = delegator.networkLimit(tanssi.subnetwork(0));
        if (networkLimit == 0) {
            console2.log("Setting network limit for", _delegator);
            uint256 maxLimit = delegator.maxNetworkLimit(tanssi.subnetwork(0));
            networkLimit = Math.min(maxLimit, _limit);

            delegator.setNetworkLimit(tanssi.subnetwork(0), networkLimit);
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

    function _saveTotalShares() private {
        totalSharesA.mevRestakedETH = _getTotalShares(vaultsAddressesDeployedA.mevRestakedETH.delegator);
        totalSharesA.mevCapitalETH = _getTotalShares(vaultsAddressesDeployedA.mevCapitalETH.delegator);
        totalSharesA.hashKeyCloudETH = _getTotalShares(vaultsAddressesDeployedA.hashKeyCloudETH.delegator);
        totalSharesA.renzoRestakedETH = _getTotalShares(vaultsAddressesDeployedA.renzoRestakedETH.delegator);
        totalSharesA.re7LabsETH = _getTotalShares(vaultsAddressesDeployedA.re7LabsETH.delegator);
        totalSharesA.re7LabsRestakingETH = _getTotalShares(vaultsAddressesDeployedA.re7LabsRestakingETH.delegator);
        totalSharesA.cp0xLrtETH = _getTotalShares(vaultsAddressesDeployedA.cp0xLrtETH.delegator);
        totalSharesA.etherfiwstETH = _getTotalShares(vaultsAddressesDeployedA.etherfiwstETH.delegator);
        totalSharesA.restakedLsETHVault = _getTotalShares(vaultsAddressesDeployedA.restakedLsETHVault.delegator);
        totalSharesA.opslayer = _getTotalShares(vaultsAddressesDeployedA.opslayer.delegator);

        totalSharesB.gauntletRestakedcBETH = _getTotalShares(vaultsAddressesDeployedB.gauntletRestakedcBETH.delegator);
        totalSharesB.gauntletRestakedRETH = _getTotalShares(vaultsAddressesDeployedB.gauntletRestakedRETH.delegator);
        totalSharesB.gauntletRestakedSwETH = _getTotalShares(vaultsAddressesDeployedB.gauntletRestakedSwETH.delegator);
        totalSharesB.gauntletRestakedWBETH = _getTotalShares(vaultsAddressesDeployedB.gauntletRestakedWBETH.delegator);
        totalSharesB.gauntletRestakedWstETH = _getTotalShares(vaultsAddressesDeployedB.gauntletRestakedWstETH.delegator);
    }

    function _getTotalShares(
        address delegator
    ) private view returns (uint256 totalShares) {
        totalShares = INetworkRestakeDelegator(delegator).totalOperatorNetworkShares(tanssi.subnetwork(0));
    }

    function _getMaximumAvailableStakeForVault(
        address delegator,
        uint256 vaultActiveStake
    ) private view returns (uint256 maximumAvailableStake) {
        maximumAvailableStake =
            Math.min(INetworkRestakeDelegator(delegator).networkLimit(tanssi.subnetwork(0)), vaultActiveStake);
    }

    function _saveAllOperatorPowers() private {
        _saveOperatorPowersPerVault(operators.operator1PierTwo);
        _saveOperatorPowersPerVault(operators.operator2P2P);
        _saveOperatorPowersPerVault(operators.operator3Nodeinfra);
        _saveOperatorPowersPerVault(operators.operator4Blockscape);
        _saveOperatorPowersPerVault(operators.operator5QuantNode);
        _saveOperatorPowersPerVault(operators.operator6NodeMonster);
        _saveOperatorPowersPerVault(operators.operator7BlockBones);
        _saveOperatorPowersPerVault(operators.operator8CP0XStakrspace);
        _saveOperatorPowersPerVault(operators.operator9HashkeyCloud);
        _saveOperatorPowersPerVault(operators.operator10Alchemy);
        _saveOperatorPowersPerVault(operators.operator11Opslayer);
    }

    function _saveOperatorPowersPerVault(
        HelperConfig.OperatorData storage operator
    ) private {
        for (uint256 i; i < operator.vaults.length;) {
            operator.powers.push(
                reader.getOperatorPower(operator.evmAddress, operator.vaults[i], tanssi.subnetwork(0).identifier())
            );
            unchecked {
                ++i;
            }
        }
    }

    function _checkOperatorVaultPairs(
        Middleware.OperatorVaultPair[] memory operatorVaultPairs,
        HelperConfig.OperatorData memory operator,
        uint256 totalVaults
    ) private pure {
        bool found;
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            if (operatorVaultPairs[i].operator == operator.evmAddress) {
                found = true;
                assertEq(operatorVaultPairs[i].vaults.length, totalVaults);
                assertEq(operator.vaults.length, totalVaults);
            }
        }
        assertEq(found, true, "Operator not found");
    }

    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        (, address operatorRegistryAddress,, address vaultFactoryAddress,,,,,) = helperConfig.activeNetworkConfig();

        assertEq(reader.NETWORK(), tanssi);
        assertEq(reader.OPERATOR_REGISTRY(), operatorRegistryAddress);
        assertEq(reader.VAULT_REGISTRY(), vaultFactoryAddress);
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(reader.SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(reader.subnetworksLength(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public view {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs = reader.getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, TOTAL_OPERATORS);

        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator1PierTwo, PIER_TWO_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator2P2P, P2P_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator8CP0XStakrspace, CP0X_STAKRSPACE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator3Nodeinfra, NODE_INFRA);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator4Blockscape, BLOCKSCAPE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator5QuantNode, QUANT_NODE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator6NodeMonster, NODE_MONSTER_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator7BlockBones, BLOCK_BONES_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator9HashkeyCloud, HASHKEY_CLOUD_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator10Alchemy, ALCHEMY_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator11Opslayer, OPSLAYER_VAULTS);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch = reader.getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].power, validatorsPreviousEpoch[0].power);
        assertEq(validators[1].power, validatorsPreviousEpoch[1].power);
        assertEq(validators[2].power, validatorsPreviousEpoch[2].power);
        assertEq(validators[0].key, validatorsPreviousEpoch[0].key);
        assertEq(validators[1].key, validatorsPreviousEpoch[1].key);
        assertEq(validators[2].key, validatorsPreviousEpoch[2].key);
    }

    function testPowerIsExpectedAccordingToOraclePrice() public view {
        uint256 currentPower = reader.getOperatorPower(
            operators.operator5QuantNode.evmAddress,
            vaultsAddressesDeployedA.re7LabsETH.vault,
            tanssi.subnetwork(0).identifier()
        );
        uint256 stake = IBaseDelegator(IVault(vaultsAddressesDeployedA.re7LabsETH.vault).delegator()).stake(
            tanssi.subnetwork(0), operators.operator5QuantNode.evmAddress
        );

        (, int256 oraclePrice,,,) = AggregatorV3Interface(tokensConfig.wstETH.oracle).latestRoundData();
        uint8 oraclePriceDecimals = AggregatorV3Interface(tokensConfig.wstETH.oracle).decimals();

        uint256 expectedPower = (stake * uint256(oraclePrice)) / 10 ** oraclePriceDecimals;
        assertEq(currentPower, expectedPower);
    }

    function testWithdrawForEachVault() public {
        HelperConfig.OperatorData memory operator = operators.operator1PierTwo;

        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.etherfiwstETH, operator, WHITELIST_SETTER_ETHERFIWSTETH
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.gauntletRestakedcBETH, operator, VAULT_MANAGER_GAUNTLET
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.gauntletRestakedRETH, operator, VAULT_MANAGER_GAUNTLET
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.gauntletRestakedSwETH, operator, VAULT_MANAGER_GAUNTLET
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.gauntletRestakedWBETH, operator, VAULT_MANAGER_GAUNTLET
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.gauntletRestakedWstETH, operator, VAULT_MANAGER_GAUNTLET
        );
        _testWithdrawFromVaultByOperator(vaultsAddressesDeployedA.mevRestakedETH, operator, VAULT_MANAGER_COMMON);
        _testWithdrawFromVaultByOperator(vaultsAddressesDeployedA.renzoRestakedETH, operator, VAULT_MANAGER_COMMON);
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.restakedLsETHVault, operator, VAULT_MANAGER_RESTAKEDLSETHVAULT
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.re7LabsETH, operators.operator2P2P, VAULT_MANAGER_COMMON
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.mevCapitalETH, operators.operator3Nodeinfra, WHITELIST_SETTER_MEVCAPITAL
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.hashKeyCloudETH, operators.operator9HashkeyCloud, VAULT_MANAGER_COMMON
        );

        // CP0x has reached deposit limit so we need to set it first
        vm.startPrank(VAULT_MANAGER_CP0XLRTETH);
        IVault(vaultsAddressesDeployedA.cp0xLrtETH.vault).setDepositLimit(10_000 ether);
        vm.stopPrank();
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.cp0xLrtETH, operators.operator8CP0XStakrspace, VAULT_MANAGER_COMMON
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.opslayer, operators.operator11Opslayer, VAULT_MANAGER_OPSLAYER
        );
    }

    function _testWithdrawFromVaultByOperator(
        HelperConfig.VaultData memory vaultData,
        HelperConfig.OperatorData memory operator,
        address whitelistSetter
    ) private {
        IVault vault = IVault(vaultData.vault);
        address operatorAddress = operator.evmAddress;
        uint256 activeBalanceOf = vault.activeBalanceOf(operatorAddress);

        if (activeBalanceOf == 0) {
            if (vault.depositWhitelist() && !vault.isDepositorWhitelisted(operatorAddress)) {
                if (IAccessControl(address(vault)).hasRole(DEPOSIT_WHITELIST_SET_ROLE, whitelistSetter)) {
                    vm.startPrank(whitelistSetter);
                    vault.setDepositorWhitelistStatus(operatorAddress, true);
                } else {
                    // Fail, needs to be configured in the test
                    revert(
                        string(
                            abi.encodePacked(
                                "Operator is not whitelisted and cannot whitelist depositor for vault", vaultData.name
                            )
                        )
                    );
                }
            }

            vm.startPrank(operatorAddress);
            _depositToVault(vault, operatorAddress, MIN_DEPOSIT, IERC20(vault.collateral()));
        }

        vm.warp(block.timestamp + 7 days + 1);
        uint256 initialEpoch = vault.currentEpoch();

        activeBalanceOf = vault.activeBalanceOf(operatorAddress);
        uint256 withdrawAmount = activeBalanceOf / 10; // Withdraw amount = 10% of balance

        // Get current operator balance of the vault collateral
        IERC20 collateral = IERC20(vault.collateral());
        uint256 initialBalance = collateral.balanceOf(operatorAddress);

        vm.startPrank(operatorAddress);
        vault.withdraw(operatorAddress, withdrawAmount);

        // Warp the epoch duration * 2
        vm.warp(block.timestamp + vault.epochDuration() * 2 + 1);

        // Claim for the right epoch (1 after withdraw started)
        vault.claim(operatorAddress, initialEpoch + 1);

        // Check new balance, assert difference equals withdraw amount
        uint256 finalBalance = collateral.balanceOf(operatorAddress);
        assertEq(finalBalance - initialBalance, withdrawAmount);
        vm.stopPrank();
    }

    function testPauseAndUnregisterOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);
        vm.startPrank(admin);
        middleware.pauseOperator(operators.operator1PierTwo.evmAddress);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);

        middleware.unregisterOperator(operators.operator1PierTwo.evmAddress);
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS - 1); // One less operator

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        middleware.registerOperator(operators.operator1PierTwo.evmAddress, abi.encode(bytes32(uint256(12))), address(0));

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS); // One more operator
    }

    function testPauseAndUnpausingOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);

        vm.startPrank(admin);
        middleware.pauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS - 1); // One less operator

        middleware.unpauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, TOTAL_OPERATORS);
    }

    function testOldUpkeep() public {
        vm.prank(admin);
        middleware.setForwarder(forwarder);
        // It's not needed (anyone can call it), it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        vm.prank(offlineKeepers);
        uint256 beforeGas = gasleft();
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        uint256 afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        bytes32[] memory sortedKeys = abi.decode(performData, (bytes32[]));
        assertEq(sortedKeys.length, TOTAL_OPERATORS);
        assertLe(performData.length, MAX_CHAINLINK_PROCESSABLE_BYTES);

        vm.prank(forwarder);
        beforeGas = gasleft();
        vm.expectEmit(true, false, false, false);
        emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
        middleware.performUpkeep(performData);
        afterGas = gasleft();
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_PERFORMUPKEEP_GAS); // Check that gas is lower than 5M limit

        (upkeepNeeded,) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);
    }

    function testUpkeep() public {
        vm.prank(admin);
        middleware.setForwarder(forwarder);
        // It's not needed (anyone can call it), it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");

        // TODO: The upgrade is needed only because it didn't happen on mainnet yet
        DeployTanssiEcosystem deployTanssiEcosystem = new DeployTanssiEcosystem();
        address stakerRewardsFactory = middleware.i_stakerRewardsFactory();
        deployTanssiEcosystem.upgradeMiddleware(address(middleware), 1, admin);

        OBaseMiddlewareReader newReader = new OBaseMiddlewareReader();
        vm.prank(admin);
        middleware.setReader(address(newReader));
        // Remove the code on top once mainnet is upgraded

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        vm.prank(offlineKeepers);
        uint256 beforeGas = gasleft();
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        uint256 afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        (uint8 command, IMiddleware.ValidatorData[] memory validatorsData) =
            abi.decode(performData, (uint8, IMiddleware.ValidatorData[]));
        assertEq(command, middleware.CACHE_DATA_COMMAND());
        assertEq(validatorsData.length, TOTAL_OPERATORS);

        vm.prank(forwarder);
        beforeGas = gasleft();
        middleware.performUpkeep(performData);
        afterGas = gasleft();
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        beforeGas = gasleft();
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        bytes32[] memory sortedKeys;
        (command, sortedKeys) = abi.decode(performData, (uint8, bytes32[]));
        assertEq(command, middleware.SEND_DATA_COMMAND());
        assertEq(sortedKeys.length, TOTAL_OPERATORS);

        vm.prank(forwarder);
        beforeGas = gasleft();
        vm.expectEmit(true, false, false, false);
        emit IOGateway.OperatorsDataCreated(sortedKeys.length, hex"");
        middleware.performUpkeep(performData);
        afterGas = gasleft();
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_PERFORMUPKEEP_GAS); // Check that gas is lower than 5M limit

        (upkeepNeeded,) = middleware.checkUpkeep(hex"");
        assertEq(upkeepNeeded, false);
    }

    function testMiddlewareIsUpgradeable() public {
        Middleware middlewareImpl = new Middleware();

        vm.startPrank(admin);
        assertEq(middleware.VERSION(), 1);

        MiddlewareV2 middlewareImplV2 = new MiddlewareV2();
        bytes memory emptyBytes = hex"";
        middleware.upgradeToAndCall(address(middlewareImplV2), emptyBytes);

        assertEq(middleware.VERSION(), 2);

        vm.expectRevert(); //Function doesn't exists
        middleware.setGateway(address(gateway));

        middleware.upgradeToAndCall(address(middlewareImpl), emptyBytes);
        assertEq(middleware.VERSION(), 1);

        vm.expectRevert(IMiddleware.Middleware__AlreadySet.selector);
        middleware.setGateway(address(gateway));
        assertEq(middleware.getGateway(), address(gateway));
    }

    function testSlashingAndVetoingSlashForPierTwoResultInNoChange() public {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);
        uint256 operatorPowerBefore;
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i].key == operators.operator1PierTwo.operatorKey) {
                operatorPowerBefore = validators[i].power;
                break;
            }
        }
        assertGe(operatorPowerBefore, 0);

        vm.prank(address(gateway));
        middleware.slash(currentEpoch, operators.operator1PierTwo.operatorKey, SLASHING_FRACTION);

        // We need to veto the slashes for all the vaults of the operator
        for (uint256 i = 0; i < operators.operator1PierTwo.vaults.length; i++) {
            IVault vault = IVault(operators.operator1PierTwo.vaults[i]);
            IVetoSlasher slasher = IVetoSlasher(vault.slasher());
            address resolver = slasher.resolver(tanssi.subnetwork(0), new bytes(0));
            // This is actually not needed since slashes need to be executed to take place. Vetoing just prevents that from being possible. However we leave it here for completeness.
            if (resolver != address(0)) {
                vm.prank(resolver);
                slasher.vetoSlash(0, hex"");
                vm.stopPrank();
            }
        }

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(newEpoch);

        uint256 operatorPowerAfter;
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i].key == operators.operator1PierTwo.operatorKey) {
                operatorPowerAfter = validators[i].power;
                break;
            }
        }
        assertEq(operatorPowerBefore, operatorPowerAfter);
    }

    function testSlashingAndExecutingSlashForOperator1PierTwo() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator1PierTwo);
    }

    function testSlashingAndExecutingSlashForOperator2P2P() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator2P2P);
    }

    function testSlashingAndExecutingSlashForOperator3Nodeinfra() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator3Nodeinfra);
    }

    function testSlashingAndExecutingSlashForOperator4Blockscape() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator4Blockscape);
    }

    function testSlashingAndExecutingSlashForOperator5QuantNode() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator5QuantNode);
    }

    function testSlashingAndExecutingSlashForOperator6NodeMonster() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator6NodeMonster);
    }

    function testSlashingAndExecutingSlashForOperator7BlockBones() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator7BlockBones);
    }

    function testSlashingAndExecutingSlashForOperator8CP0XStakrspace() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator8CP0XStakrspace);
    }

    function testSlashingAndExecutingSlashForOperator9HashkeyCloud() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator9HashkeyCloud);
    }

    function testSlashingAndExecutingSlashForOperator10Alchemy() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator10Alchemy);
    }

    function testSlashingAndExecutingSlashForOperator11Opslayer() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator11Opslayer);
    }

    // Case 1 has rewards for pier two, p2p, nodeinfra and blockscape. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase1() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(1);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2P2P.points
                + proofAndPointsByOperator.operator3Nodeinfra.points + proofAndPointsByOperator.operator4Blockscape.points
        );

        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator2P2P, proofAndPointsByOperator.operator2P2P, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator3Nodeinfra, proofAndPointsByOperator.operator3Nodeinfra, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator4Blockscape, proofAndPointsByOperator.operator4Blockscape, totalPoints
        );
    }

    // Case 2 has rewards for quant node, node monster, block bones and cp0x stakrspace. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase2() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(2);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator5QuantNode.points + proofAndPointsByOperator.operator6NodeMonster.points
                + proofAndPointsByOperator.operator7BlockBones.points
                + proofAndPointsByOperator.operator8CP0XStakrspace.points
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator5QuantNode, proofAndPointsByOperator.operator5QuantNode, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator6NodeMonster, proofAndPointsByOperator.operator6NodeMonster, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator7BlockBones, proofAndPointsByOperator.operator7BlockBones, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator8CP0XStakrspace, proofAndPointsByOperator.operator8CP0XStakrspace, totalPoints
        );
    }

    // Case 3 has rewards for pier two, p2p, alchemy and opslayer. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase3() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2P2P.points
                + proofAndPointsByOperator.operator10Alchemy.points + proofAndPointsByOperator.operator11Opslayer.points
        );

        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator2P2P, proofAndPointsByOperator.operator2P2P, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator10Alchemy, proofAndPointsByOperator.operator10Alchemy, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, totalPoints
        );
    }

    // Case 4 has rewards for all operators. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase4() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(4);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2P2P.points
                + proofAndPointsByOperator.operator3Nodeinfra.points + proofAndPointsByOperator.operator4Blockscape.points
                + proofAndPointsByOperator.operator5QuantNode.points + proofAndPointsByOperator.operator6NodeMonster.points
                + proofAndPointsByOperator.operator7BlockBones.points
                + proofAndPointsByOperator.operator8CP0XStakrspace.points
                + proofAndPointsByOperator.operator9HashkeyCloud.points + proofAndPointsByOperator.operator10Alchemy.points
                + proofAndPointsByOperator.operator11Opslayer.points
        );

        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator2P2P, proofAndPointsByOperator.operator2P2P, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator3Nodeinfra, proofAndPointsByOperator.operator3Nodeinfra, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator4Blockscape, proofAndPointsByOperator.operator4Blockscape, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator5QuantNode, proofAndPointsByOperator.operator5QuantNode, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator6NodeMonster, proofAndPointsByOperator.operator6NodeMonster, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator7BlockBones, proofAndPointsByOperator.operator7BlockBones, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator8CP0XStakrspace, proofAndPointsByOperator.operator8CP0XStakrspace, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator9HashkeyCloud, proofAndPointsByOperator.operator9HashkeyCloud, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator10Alchemy, proofAndPointsByOperator.operator10Alchemy, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, totalPoints
        );
    }

    function testStakerRewardsDistributionCase1() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(1);

        _claimAndCheckRewardsForStaker(
            operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator2P2P, proofAndPointsByOperator.operator2P2P, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator3Nodeinfra, proofAndPointsByOperator.operator3Nodeinfra, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator4Blockscape, proofAndPointsByOperator.operator4Blockscape, eraIndex, totalPoints
        );
    }

    function testStakerRewardsDistributionCase2() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(2);

        _claimAndCheckRewardsForStaker(
            operators.operator5QuantNode, proofAndPointsByOperator.operator5QuantNode, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator6NodeMonster, proofAndPointsByOperator.operator6NodeMonster, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator7BlockBones, proofAndPointsByOperator.operator7BlockBones, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator8CP0XStakrspace, proofAndPointsByOperator.operator8CP0XStakrspace, eraIndex, totalPoints
        );
    }

    function testStakerRewardsDistributionCase3() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        _claimAndCheckRewardsForStaker(
            operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator2P2P, proofAndPointsByOperator.operator2P2P, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator10Alchemy, proofAndPointsByOperator.operator10Alchemy, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, eraIndex, totalPoints
        );
    }

    function testStakerRewardsDistributionCase4() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(4);

        _claimAndCheckRewardsForStaker(
            operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator2P2P, proofAndPointsByOperator.operator2P2P, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator3Nodeinfra, proofAndPointsByOperator.operator3Nodeinfra, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator4Blockscape, proofAndPointsByOperator.operator4Blockscape, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator5QuantNode, proofAndPointsByOperator.operator5QuantNode, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator6NodeMonster, proofAndPointsByOperator.operator6NodeMonster, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator7BlockBones, proofAndPointsByOperator.operator7BlockBones, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator8CP0XStakrspace, proofAndPointsByOperator.operator8CP0XStakrspace, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator9HashkeyCloud, proofAndPointsByOperator.operator9HashkeyCloud, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator10Alchemy, proofAndPointsByOperator.operator10Alchemy, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, eraIndex, totalPoints
        );
    }

    function testTanssiVaultCanBeRegisteredAndOperatorCanOptIn() public {
        HelperConfig.VaultData memory vaultData = _configureTanssiVault();
        (,,,,, address operatorVaultOptInServiceAddress,,,) = helperConfig.activeNetworkConfig();

        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);
        bool optedIn = operatorVaultOptInService.isOptedIn(operators.operator11Opslayer.evmAddress, vaultData.vault);
        assertTrue(optedIn);

        assertEq(2, operators.operator11Opslayer.vaults.length);

        uint256 expectedPower =
            TANSSI_VAULT_DEPOSIT_AMOUNT.mulDiv(uint256(TANSSI_ORACLE_CONVERSION_TOKEN), 10 ** TANSSI_ORACLE_DECIMALS);
        // TANSSI is 12 decimals, we must adjust it to the generic 18.
        uint256 adjustedDecimalsPower = expectedPower.mulDiv(10 ** 18, 10 ** (rewardsToken.decimals()));
        assertEq(adjustedDecimalsPower, operators.operator11Opslayer.powers[1]);
    }

    function testTanssiVaultCanDistributeOperatorRewards() public {
        _configureTanssiVault();

        // We reuse case 3 were opslayer has rewards.
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2P2P.points
                + proofAndPointsByOperator.operator10Alchemy.points + proofAndPointsByOperator.operator11Opslayer.points
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, totalPoints
        );
    }

    function testTanssiVaultCanDistributeStakerRewards() public {
        _configureTanssiVault();

        // We reuse case 3 were opslayer has rewards.
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        _claimAndCheckRewardsForStaker(
            operators.operator11Opslayer, proofAndPointsByOperator.operator11Opslayer, eraIndex, totalPoints
        );
    }

    function testTanssiVaultCanGetSlashed() public {
        HelperConfig.VaultData memory vaultData = _configureTanssiVault();

        uint48 initialEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = reader.getEpochStart(initialEpoch);
        HelperConfig.OperatorData memory operator = operators.operator11Opslayer;

        uint256 vaultBalanceBefore = rewardsToken.balanceOf(vaultData.vault);
        uint256 operatorStakeBefore = IBaseDelegator(IVault(vaultData.vault).delegator()).stakeAt(
            tanssi.subnetwork(0), operator.evmAddress, epochStartTs, new bytes(0)
        );
        uint256 expectedSlash = operatorStakeBefore.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);

        // We need to track by stake and not by power since power uses live oracle which cannot be mocked
        vm.prank(address(gateway));
        middleware.slash(initialEpoch, operator.operatorKey, SLASHING_FRACTION);

        uint256 vaultBalanceAfter = rewardsToken.balanceOf(vaultData.vault);
        assertEq(vaultBalanceBefore - expectedSlash, vaultBalanceAfter);
    }

    function _configureTanssiVault() private returns (HelperConfig.VaultData memory vaultData) {
        (address vaultConfigurator,,,,,, address networkMiddlewareService,,) = helperConfig.activeNetworkConfig();
        console2.log("vaultConfigurator", vaultConfigurator);
        console2.log("networkMiddlewareService", networkMiddlewareService);
        stakerRewardsImpl = address(new ODefaultStakerRewards(networkMiddlewareService, tanssi));

        // TODO: Remove when factory is fixed, currently it points the wrong network and operator rewards
        {
            (,,, address vaultRegistry,,,,,) = helperConfig.activeNetworkConfig();
            DeployRewards deployRewards = new DeployRewards();
            address stakerRewardsFactory = deployRewards.deployStakerRewardsFactoryContract(
                vaultRegistry, networkMiddlewareService, address(operatorRewards), tanssi, admin
            );
            vm.allowCheatcodes(0x9eb0Ff9A553416Ac9Ec87881aB2ecC4879AdbC21); // No freaking clue why this is needed

            DeployTanssiEcosystem deployTanssiEcosystem = new DeployTanssiEcosystem();
            deployTanssiEcosystem.upgradeMiddleware(address(middleware), 1, admin);
            address newReader = address(new OBaseMiddlewareReader());
            vm.startPrank(admin);
            ODefaultStakerRewardsFactory(stakerRewardsFactory).setImplementation(stakerRewardsImpl);
            middleware.setReader(newReader);
            middleware.reinitializeRewards(address(operatorRewards), address(stakerRewardsFactory));
            vm.stopPrank();
        }
        // Remove until here

        DeployVault deployVault = new DeployVault();
        (address tanssiVaultAddress, address tanssiDelegatorAddress, address tanssiSlasherAddress) =
            deployVault.createTanssiVault(vaultConfigurator, address(admin), address(rewardsToken));
        IVault tanssiVault = IVault(tanssiVaultAddress);

        DIAOracleMock tanssiOracle =
            new DIAOracleMock("TANSSI/USD", uint128(uint256(TANSSI_ORACLE_CONVERSION_TOKEN)), uint128(block.timestamp));

        AggregatorV3Proxy aggregatorTanssi = new AggregatorV3Proxy(address(tanssiOracle), "TANSSI/USD");

        vm.startPrank(admin);

        middleware.setCollateralToOracle(address(rewardsToken), address(aggregatorTanssi));
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: admin,
            adminFeeClaimRoleHolder: admin,
            adminFeeSetRoleHolder: admin,
            implementation: stakerRewardsImpl
        });
        middleware.registerSharedVault(tanssiVaultAddress, stakerRewardsParams);
        vaultToStakerRewards[tanssiVaultAddress] = operatorRewards.vaultToStakerRewardsContract(tanssiVaultAddress);

        address operator = operators.operator11Opslayer.evmAddress;

        vm.startPrank(operator);
        _depositToVault(tanssiVault, operator, TANSSI_VAULT_DEPOSIT_AMOUNT, rewardsToken);

        vaultData = HelperConfig.VaultData({
            name: "Tanssi Vault",
            vault: tanssiVaultAddress,
            delegator: tanssiDelegatorAddress,
            slasher: tanssiSlasherAddress,
            collateral: address(rewardsToken),
            stakerRewards: vaultToStakerRewards[tanssiVaultAddress]
        });
        _optInOperator(operator, vaultData, tanssi, admin);

        vm.startPrank(tanssi);

        _setMaxNetworkLimitIfNeeded(tanssiDelegatorAddress, MAX_NETWORK_LIMIT);
        _setNetworkLimitIfNeeded(admin, tanssiDelegatorAddress, OPERATOR_NETWORK_LIMIT);

        vm.startPrank(admin);
        _setSharesIfNeeded(tanssiDelegatorAddress, operator, OPERATOR_SHARE);

        vm.stopPrank();

        vm.warp(block.timestamp + 7 days + 1);

        operators.operator11Opslayer.vaults.push(tanssiVaultAddress);
        uint256 operatorPower = reader.getOperatorPower(operator, tanssiVaultAddress, tanssi.subnetwork(0).identifier());
        operators.operator11Opslayer.powers.push(operatorPower);
    }

    function _claimAndCheckRewardsForOperator(
        uint48 eraIndex,
        HelperConfig.OperatorData memory operator,
        ProofAndPoints memory proofAndPoints,
        uint256 totalPoints
    ) private returns (uint256 expectedRewardsForStakers) {
        bytes memory additionalData = abi.encode(MAX_ADMIN_FEE_BPS, new bytes(0), new bytes(0));
        uint256 previousBalance = rewardsToken.balanceOf(operator.evmAddress);
        IODefaultOperatorRewards.ClaimRewardsInput memory claimRewardsData = IODefaultOperatorRewards.ClaimRewardsInput({
            operatorKey: operator.operatorKey,
            eraIndex: eraIndex,
            totalPointsClaimable: proofAndPoints.points,
            proof: proofAndPoints.proof,
            data: additionalData
        });
        operatorRewards.claimRewards(claimRewardsData);

        uint256 newBalance = rewardsToken.balanceOf(operator.evmAddress);
        uint256 expectedRewardsForOperator = TOKEN_REWARDS_PER_ERA_INDEX.mulDiv(proofAndPoints.points, totalPoints)
            .mulDiv(OPERATOR_SHARE, MAX_PERCENTAGE);
        expectedRewardsForStakers =
            TOKEN_REWARDS_PER_ERA_INDEX.mulDiv(proofAndPoints.points, totalPoints) - expectedRewardsForOperator;

        assertEq(newBalance - previousBalance, expectedRewardsForOperator);
    }

    function _claimAndCheckRewardsForStaker(
        HelperConfig.OperatorData memory operator,
        ProofAndPoints memory proofAndPoints,
        uint48 eraIndex,
        uint32 totalPoints
    ) private {
        uint256 totalVaults = operator.vaults.length;

        // Implementations of Staker Rewards contracts can vary, so the only safe way we can know they are receiving the correct amount of rewards is by checking the balance of the staker rewards contract before and after the operator claims rewards
        uint256[] memory stakerRewardsBalancesBefore = new uint256[](totalVaults);
        uint256 totalPower;
        for (uint256 i; i < totalVaults; i++) {
            address vault = operator.vaults[i];
            stakerRewardsBalancesBefore[i] = rewardsToken.balanceOf(vaultToStakerRewards[vault]);

            totalPower += operator.powers[i];
        }

        uint256 expectedStakerRewards =
            _claimAndCheckRewardsForOperator(eraIndex, operator, proofAndPoints, totalPoints);

        for (uint256 i; i < totalVaults; i++) {
            uint256 expectedStakerRewardsForVault = expectedStakerRewards.mulDiv(operator.powers[i], totalPower);
            uint256 newStakerRewardsBalancesBefore = rewardsToken.balanceOf(vaultToStakerRewards[operator.vaults[i]]);
            uint256 actualRewards = newStakerRewardsBalancesBefore - stakerRewardsBalancesBefore[i];
            assertApproxEqAbs(actualRewards, expectedStakerRewardsForVault, 10);
        }
    }

    function _prepareRewardsDistributionForCase(
        uint48 caseIndex
    ) private returns (uint48 eraIndex, uint32 totalPoints) {
        bytes32 rewardsRoot;
        (rewardsRoot, totalPoints) = _loadAllRewardsRootProofsAndPointsForCase(caseIndex);

        eraIndex = _mintAndDistributeRewards(caseIndex, rewardsRoot, totalPoints);
    }

    function _loadAllRewardsRootProofsAndPointsForCase(
        uint48 caseIndex
    ) private returns (bytes32 rewardsRoot, uint32 totalPoints) {
        (proofAndPointsByOperator.operator1PierTwo.proof, proofAndPointsByOperator.operator1PierTwo.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "PierTwo");
        (proofAndPointsByOperator.operator2P2P.proof, proofAndPointsByOperator.operator2P2P.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "P2P");
        (proofAndPointsByOperator.operator3Nodeinfra.proof, proofAndPointsByOperator.operator3Nodeinfra.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Nodeinfra");
        (proofAndPointsByOperator.operator4Blockscape.proof, proofAndPointsByOperator.operator4Blockscape.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Blockscape");
        (proofAndPointsByOperator.operator5QuantNode.proof, proofAndPointsByOperator.operator5QuantNode.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "QuantNode");
        (proofAndPointsByOperator.operator6NodeMonster.proof, proofAndPointsByOperator.operator6NodeMonster.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "NodeMonster");
        (proofAndPointsByOperator.operator7BlockBones.proof, proofAndPointsByOperator.operator7BlockBones.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "BlocknBones");
        (
            proofAndPointsByOperator.operator8CP0XStakrspace.proof,
            proofAndPointsByOperator.operator8CP0XStakrspace.points
        ) = _loadRewardsProofAndPointsForOperator(caseIndex, "CP0X");
        (proofAndPointsByOperator.operator9HashkeyCloud.proof, proofAndPointsByOperator.operator9HashkeyCloud.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "HashkeyCloud");
        (proofAndPointsByOperator.operator10Alchemy.proof, proofAndPointsByOperator.operator10Alchemy.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Alchemy");
        (proofAndPointsByOperator.operator11Opslayer.proof, proofAndPointsByOperator.operator11Opslayer.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Opslayer");

        string memory base = string.concat("$.", vm.toString(caseIndex), ".");

        string memory key = string.concat(base, "root");
        rewardsRoot = vm.parseJsonBytes32(json, key);

        key = string.concat(base, "total_points");
        totalPoints = uint32(vm.parseJsonUint(json, key));
    }

    function _loadRewardsProofAndPointsForOperator(
        uint48 index,
        string memory operator
    ) private view returns (bytes32[] memory proof, uint32 points) {
        string memory base = string.concat("$.", vm.toString(index), ".");

        string memory key = string.concat(base, operator, ".proof");
        try vm.parseJsonBytes32Array(json, key) returns (bytes32[] memory proof_) {
            proof = proof_;
            key = string.concat(base, operator, ".points");
            points = uint32(vm.parseJsonUint(json, key));
        } catch {
            proof = new bytes32[](0);
            points = 0;
        }
    }

    function _mintAndDistributeRewards(
        uint48 caseIndex,
        bytes32 rewardsRoot,
        uint32 totalPoints
    ) private returns (uint48 eraIndex) {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint48 epoch = currentEpoch + caseIndex;

        eraIndex = epoch * 4;
        uint48 epochStartTs = middleware.getEpochStart(epoch);
        vm.warp(epochStartTs + 1);

        vm.startPrank(address(gateway));

        rewardsToken.mint(address(middleware), TOKEN_REWARDS_PER_ERA_INDEX);

        middleware.distributeRewards(
            epoch, eraIndex, totalPoints, TOKEN_REWARDS_PER_ERA_INDEX, rewardsRoot, address(rewardsToken)
        );

        vm.stopPrank();
    }

    function _testSlashingAndExecutingSlashForOperator(
        HelperConfig.OperatorData memory operator
    ) public {
        uint48 initialEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = reader.getEpochStart(initialEpoch);

        // We need to track by stake and not by power since power uses live oracle which cannot be mocked
        vm.prank(address(gateway));
        middleware.slash(initialEpoch, operator.operatorKey, SLASHING_FRACTION);

        vm.warp(block.timestamp + VETO_DURATION + 1);

        // We need to execute the slashes for all the vaults of the operator
        address[] memory vaults = operator.vaults;
        for (uint256 i; i < vaults.length; i++) {
            address vault = vaults[i];
            address vaultCollateral = middleware.vaultToCollateral(vault);
            uint256 vaultBalanceBefore = IERC20(vaultCollateral).balanceOf(vault);
            uint256 operatorStakeBefore = IBaseDelegator(IVault(vault).delegator()).stakeAt(
                tanssi.subnetwork(0), operator.evmAddress, epochStartTs, new bytes(0)
            );
            uint256 expectedSlash = operatorStakeBefore.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);

            uint256 slashedAmount = middleware.executeSlash(vault, 0, hex"");
            uint256 vaultBalanceAfter = IERC20(vaultCollateral).balanceOf(vault);

            assertEq(slashedAmount, expectedSlash);
            assertEq(vaultBalanceBefore - slashedAmount, vaultBalanceAfter);
        }
    }
}
