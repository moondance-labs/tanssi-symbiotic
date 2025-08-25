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
import {AggregatorV3DIAProxy} from "src/contracts/oracle-proxy/AggregatorV3DIAProxy.sol";
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

    uint256 public constant PIER_TWO_VAULTS = 3;
    uint256 public constant NODE_INFRA = 3;
    uint256 public constant CP0X_STAKRSPACE_VAULTS = 1;
    uint256 public constant HASHKEY_CLOUD_VAULTS = 1;
    uint256 public constant ALCHEMY_VAULTS = 3;
    uint256 public constant OPSLAYER_VAULTS = 1;
    uint256 public constant TANSSI_FOUNDATION_VAULTS = 1;

    uint256 public constant TOTAL_OPERATORS = 7;

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
    address public constant VAULT_MANAGER_TANSSI = 0x43347365ca92539a894437fB59C78d4e6dF123a3;

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
        uint256 tanssi;
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
        uint256 tanssi;
    }

    struct ProofAndPoints {
        bytes32[] proof;
        uint32 points;
    }

    struct ProofAndPointsByOperator {
        ProofAndPoints operator1PierTwo;
        ProofAndPoints operator2Nodeinfra;
        ProofAndPoints operator3CP0XStakrspace;
        ProofAndPoints operator4HashkeyCloud;
        ProofAndPoints operator5Alchemy;
        ProofAndPoints operator6Opslayer;
        ProofAndPoints operator7TanssiFoundation;
    }

    function setUp() public {
        string memory project_root = vm.projectRoot();
        string memory path = string.concat(project_root, "/test/fork/mainnet/rewards_data.json");
        json = vm.readFile(path);

        _getBaseInfrastructure();
        _cacheAllVaultToStakerRewards();
        _cacheAllOperatorsVaults();
        _saveTotalShares();

        vm.warp(vm.getBlockTimestamp() + 14 days + 1); // In 14 days there should be a new vault epoch in all vaults

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
        _cacheVaultToStakerRewards(vaultsAddressesDeployedB.tanssi);
    }

    function _cacheAllOperatorsVaults() private {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs = reader.getOperatorVaultPairs(currentEpoch);
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            if (operatorVaultPairs[i].operator == operators.operator1PierTwo.evmAddress) {
                _cacheOperatorVaults(operators.operator1PierTwo, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator2Nodeinfra.evmAddress) {
                _cacheOperatorVaults(operators.operator2Nodeinfra, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator3CP0XStakrspace.evmAddress) {
                _cacheOperatorVaults(operators.operator3CP0XStakrspace, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator4HashkeyCloud.evmAddress) {
                _cacheOperatorVaults(operators.operator4HashkeyCloud, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator5Alchemy.evmAddress) {
                _cacheOperatorVaults(operators.operator5Alchemy, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator6Opslayer.evmAddress) {
                _cacheOperatorVaults(operators.operator6Opslayer, operatorVaultPairs[i]);
            } else if (operatorVaultPairs[i].operator == operators.operator7TanssiFoundation.evmAddress) {
                _cacheOperatorVaults(operators.operator7TanssiFoundation, operatorVaultPairs[i]);
            }
        }
    }

    function _cacheOperatorVaults(
        HelperConfig.OperatorData storage operator,
        Middleware.OperatorVaultPair memory operatorVaultPair
    ) private {
        for (uint256 i; i < operatorVaultPair.vaults.length; i++) {
            operator.vaults.push(operatorVaultPair.vaults[i]);
        }
    }

    function _cacheVaultToStakerRewards(
        HelperConfig.VaultData memory vaultData
    ) private {
        vaultToStakerRewards[vaultData.vault] = vaultData.stakerRewards;
    }

    function _depositToVault(IVault vault, address operator, uint256 amount, IERC20 collateral) public {
        deal(address(collateral), operator, amount);
        collateral.approve(address(vault), amount);
        vault.deposit(operator, amount);
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
        totalSharesB.tanssi = _getTotalShares(vaultsAddressesDeployedB.tanssi.delegator);
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
        _saveOperatorPowersPerVault(operators.operator2Nodeinfra);
        _saveOperatorPowersPerVault(operators.operator3CP0XStakrspace);
        _saveOperatorPowersPerVault(operators.operator4HashkeyCloud);
        _saveOperatorPowersPerVault(operators.operator5Alchemy);
        _saveOperatorPowersPerVault(operators.operator6Opslayer);
        _saveOperatorPowersPerVault(operators.operator7TanssiFoundation);
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
                assertGe(operatorVaultPairs[i].vaults.length, totalVaults);
                assertGe(operator.vaults.length, totalVaults);
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

    function testUpdateAndUnpause() public {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);
        console2.log("Validators length", validators.length);
        vm.startPrank(admin);
        try middleware.pauseOperator(operators.operator1PierTwo.evmAddress) {
            vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        } catch {
            console2.log("Operator is already paused");
        }

        bytes memory newKey = abi.encode(bytes32(uint256(12)));
        middleware.updateOperatorKey(operators.operator1PierTwo.evmAddress, newKey);
        middleware.unpauseOperator(operators.operator1PierTwo.evmAddress);

        vm.stopPrank();

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        console2.log("Validators length", validators.length);
        bool found = false;
        for (uint256 i; i < validators.length; i++) {
            if (validators[i].key == bytes32(uint256(12))) {
                found = true;
                break;
            }
        }
        assertEq(found, true);
    }

    function testIfOperatorsAreRegisteredInVaults() public view {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs = reader.getOperatorVaultPairs(currentEpoch);

        assertGe(operatorVaultPairs.length, TOTAL_OPERATORS);
        console2.log("Operator vault pairs length", operatorVaultPairs.length);
        console2.log("Total operators", TOTAL_OPERATORS);
        for (uint256 i; i < operatorVaultPairs.length; i++) {
            console2.log("Operator is registered:", operatorVaultPairs[i].operator);
        }

        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator1PierTwo, PIER_TWO_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator3CP0XStakrspace, CP0X_STAKRSPACE_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator2Nodeinfra, NODE_INFRA);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator4HashkeyCloud, HASHKEY_CLOUD_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator5Alchemy, ALCHEMY_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator6Opslayer, OPSLAYER_VAULTS);
        _checkOperatorVaultPairs(operatorVaultPairs, operators.operator7TanssiFoundation, TANSSI_FOUNDATION_VAULTS);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch = reader.getValidatorSet(previousEpoch);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
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
            operators.operator6Opslayer.evmAddress,
            vaultsAddressesDeployedA.opslayer.vault,
            tanssi.subnetwork(0).identifier()
        );
        uint256 stake = IBaseDelegator(IVault(vaultsAddressesDeployedA.opslayer.vault).delegator()).stake(
            tanssi.subnetwork(0), operators.operator6Opslayer.evmAddress
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
            vaultsAddressesDeployedA.mevCapitalETH, operators.operator2Nodeinfra, WHITELIST_SETTER_MEVCAPITAL
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.hashKeyCloudETH, operators.operator4HashkeyCloud, VAULT_MANAGER_COMMON
        );

        // CP0x has reached deposit limit so we need to set it first
        vm.startPrank(VAULT_MANAGER_CP0XLRTETH);
        IVault(vaultsAddressesDeployedA.cp0xLrtETH.vault).setDepositLimit(10_000 ether);
        vm.stopPrank();
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.cp0xLrtETH, operators.operator3CP0XStakrspace, VAULT_MANAGER_COMMON
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedA.opslayer, operators.operator6Opslayer, VAULT_MANAGER_OPSLAYER
        );
        _testWithdrawFromVaultByOperator(
            vaultsAddressesDeployedB.tanssi, operators.operator7TanssiFoundation, VAULT_MANAGER_TANSSI
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

        vm.warp(vm.getBlockTimestamp() + 7 days + 1);
        uint256 initialEpoch = vault.currentEpoch();

        activeBalanceOf = vault.activeBalanceOf(operatorAddress);
        uint256 withdrawAmount = activeBalanceOf / 10; // Withdraw amount = 10% of balance

        // Get current operator balance of the vault collateral
        IERC20 collateral = IERC20(vault.collateral());
        uint256 initialBalance = collateral.balanceOf(operatorAddress);

        vm.startPrank(operatorAddress);
        vault.withdraw(operatorAddress, withdrawAmount);

        // Warp the epoch duration * 2
        vm.warp(vm.getBlockTimestamp() + vault.epochDuration() * 2 + 1);

        // Claim for the right epoch (1 after withdraw started)
        vault.claim(operatorAddress, initialEpoch + 1);

        // Check new balance, assert difference equals withdraw amount
        uint256 finalBalance = collateral.balanceOf(operatorAddress);
        assertEq(finalBalance - initialBalance, withdrawAmount);
        vm.stopPrank();
    }

    function testPauseAndUnregisterOperator() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);
        uint256 totalOperatorsBefore = validators.length;
        vm.startPrank(admin);
        middleware.pauseOperator(operators.operator1PierTwo.evmAddress);
        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);

        middleware.unregisterOperator(operators.operator1PierTwo.evmAddress);
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, totalOperatorsBefore - 1); // One less operator

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        middleware.registerOperator(operators.operator1PierTwo.evmAddress, abi.encode(bytes32(uint256(12))), address(0));

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, totalOperatorsBefore); // One more operator
    }

    function testPauseAndUnpausingOperator() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = reader.getValidatorSet(currentEpoch);
        uint256 totalOperatorsBefore = validators.length;

        vm.startPrank(admin);
        middleware.pauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, totalOperatorsBefore - 1);

        middleware.unpauseOperator(operators.operator1PierTwo.evmAddress);

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        currentEpoch = middleware.getCurrentEpoch();
        validators = reader.getValidatorSet(currentEpoch);
        assertEq(validators.length, totalOperatorsBefore);
    }

    function testUpkeep() public {
        vm.prank(admin);
        middleware.setForwarder(forwarder);
        // It's not needed (anyone can call it), it's just for explaining and showing the flow
        address offlineKeepers = makeAddr("offlineKeepers");

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        vm.prank(offlineKeepers);
        uint256 beforeGas = gasleft();
        (bool upkeepNeeded, bytes memory performData) = middleware.checkUpkeep(hex"");
        uint256 afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        (uint8 command, uint48 epoch, IMiddleware.ValidatorData[] memory validatorsData) =
            abi.decode(performData, (uint8, uint48, IMiddleware.ValidatorData[]));
        assertEq(epoch, currentEpoch);
        assertEq(command, middleware.CACHE_DATA_COMMAND());
        for (uint256 i = 0; i < validatorsData.length; i++) {
            console2.log("Validator power:", validatorsData[i].power);
            console2.logBytes32(validatorsData[i].key);
        }
        assertGe(validatorsData.length, TOTAL_OPERATORS);

        vm.prank(forwarder);
        beforeGas = gasleft();
        middleware.performUpkeep(performData);
        afterGas = gasleft();
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_PERFORMUPKEEP_GAS); // Check that gas is lower than 5M limit

        beforeGas = gasleft();
        (upkeepNeeded, performData) = middleware.checkUpkeep(hex"");
        afterGas = gasleft();

        assertEq(upkeepNeeded, true);
        assertLt(beforeGas - afterGas, MAX_CHAINLINK_CHECKUPKEEP_GAS); // Check that gas is lower than 10M limit

        bytes32[] memory sortedKeys;
        (command, epoch, sortedKeys) = abi.decode(performData, (uint8, uint48, bytes32[]));
        assertEq(epoch, currentEpoch);
        assertEq(command, middleware.SEND_DATA_COMMAND());
        assertGe(sortedKeys.length, TOTAL_OPERATORS);

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

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
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

    function testSlashingAndExecutingSlashForOperator3Nodeinfra() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator2Nodeinfra);
    }

    function testSlashingAndExecutingSlashForOperator8CP0XStakrspace() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator3CP0XStakrspace);
    }

    function testSlashingAndExecutingSlashForOperator9HashkeyCloud() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator4HashkeyCloud);
    }

    function testSlashingAndExecutingSlashForOperator10Alchemy() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator5Alchemy);
    }

    function testSlashingAndExecutingSlashForOperator11Opslayer() public {
        _testSlashingAndExecutingSlashForOperator(operators.operator6Opslayer);
    }

    function testSlashingAndExecutingSlashForOperator12TanssiFoundation() public {
        // This test is custom because the tanssi foundation operator is in tanssi vault, which is instant slashable. All other vaults are veto and they need to be executed.

        uint48 initialEpoch = middleware.getCurrentEpoch();
        uint48 epochStartTs = reader.getEpochStart(initialEpoch);
        HelperConfig.OperatorData memory operator = operators.operator7TanssiFoundation;

        IERC20 tanssiVaultCollateral = IERC20(middleware.vaultToCollateral(vaultsAddressesDeployedB.tanssi.vault));
        uint256 tanssiVaultBalanceBefore = tanssiVaultCollateral.balanceOf(vaultsAddressesDeployedB.tanssi.vault);
        uint256 tanssiOperatorStakeBefore = IBaseDelegator(vaultsAddressesDeployedB.tanssi.delegator).stakeAt(
            tanssi.subnetwork(0), operator.evmAddress, epochStartTs, new bytes(0)
        );
        uint256 expectedTanssiSlash = tanssiOperatorStakeBefore.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);

        // We need to track by stake and not by power since power uses live oracle which cannot be mocked
        vm.prank(address(gateway));
        middleware.slash(initialEpoch, operator.operatorKey, SLASHING_FRACTION);

        // Tanssi vault is instant slashed. We can check already.
        uint256 tanssiVaultBalanceAfter = tanssiVaultCollateral.balanceOf(vaultsAddressesDeployedB.tanssi.vault);
        assertEq(tanssiVaultBalanceBefore - expectedTanssiSlash, tanssiVaultBalanceAfter);
    }

    // Case 1 has rewards for pier two, nodeinfra. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase1() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(1);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2Nodeinfra.points
                + proofAndPointsByOperator.operator3CP0XStakrspace.points
                + proofAndPointsByOperator.operator4HashkeyCloud.points
        );

        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator2Nodeinfra, proofAndPointsByOperator.operator2Nodeinfra, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator3CP0XStakrspace, proofAndPointsByOperator.operator3CP0XStakrspace, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator4HashkeyCloud, proofAndPointsByOperator.operator4HashkeyCloud, totalPoints
        );
    }

    // Case 2 has rewards for cp0x stakrspace. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase2() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(2);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator5Alchemy.points + proofAndPointsByOperator.operator6Opslayer.points
                + proofAndPointsByOperator.operator7TanssiFoundation.points
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator5Alchemy, proofAndPointsByOperator.operator5Alchemy, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator6Opslayer, proofAndPointsByOperator.operator6Opslayer, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex,
            operators.operator7TanssiFoundation,
            proofAndPointsByOperator.operator7TanssiFoundation,
            totalPoints
        );
    }

    // Case 4 has rewards for all operators. Defined in test/fork/mainnet/rewards_data.json
    function testOperatorRewardsDistributionCase3() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        assertGe(totalPoints, 0);
        assertEq(
            totalPoints,
            proofAndPointsByOperator.operator1PierTwo.points + proofAndPointsByOperator.operator2Nodeinfra.points
                + proofAndPointsByOperator.operator3CP0XStakrspace.points
                + proofAndPointsByOperator.operator4HashkeyCloud.points + proofAndPointsByOperator.operator5Alchemy.points
                + proofAndPointsByOperator.operator6Opslayer.points
                + proofAndPointsByOperator.operator7TanssiFoundation.points
        );

        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator2Nodeinfra, proofAndPointsByOperator.operator2Nodeinfra, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator3CP0XStakrspace, proofAndPointsByOperator.operator3CP0XStakrspace, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator4HashkeyCloud, proofAndPointsByOperator.operator4HashkeyCloud, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator5Alchemy, proofAndPointsByOperator.operator5Alchemy, totalPoints
        );
        _claimAndCheckRewardsForOperator(
            eraIndex, operators.operator6Opslayer, proofAndPointsByOperator.operator6Opslayer, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator7TanssiFoundation,
            proofAndPointsByOperator.operator7TanssiFoundation,
            eraIndex,
            totalPoints
        );
    }

    function testStakerRewardsDistributionCase1() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(1);

        _claimAndCheckRewardsForStaker(
            operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator2Nodeinfra, proofAndPointsByOperator.operator2Nodeinfra, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator3CP0XStakrspace, proofAndPointsByOperator.operator3CP0XStakrspace, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator4HashkeyCloud, proofAndPointsByOperator.operator4HashkeyCloud, eraIndex, totalPoints
        );
    }

    function testStakerRewardsDistributionCase2() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(2);

        console2.log("eraIndex", eraIndex);
        _claimAndCheckRewardsForStaker(
            operators.operator5Alchemy, proofAndPointsByOperator.operator5Alchemy, eraIndex, totalPoints
        );
        console2.log("Claimed alchemy");
        _claimAndCheckRewardsForStaker(
            operators.operator6Opslayer, proofAndPointsByOperator.operator6Opslayer, eraIndex, totalPoints
        );
        console2.log("Claimed opslayer");
        _claimAndCheckRewardsForStaker(
            operators.operator7TanssiFoundation,
            proofAndPointsByOperator.operator7TanssiFoundation,
            eraIndex,
            totalPoints
        );
        console2.log("Claimed tanssi");
    }

    function testStakerRewardsDistributionCase3() public {
        (uint48 eraIndex, uint32 totalPoints) = _prepareRewardsDistributionForCase(3);

        _claimAndCheckRewardsForStaker(
            operators.operator1PierTwo, proofAndPointsByOperator.operator1PierTwo, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator2Nodeinfra, proofAndPointsByOperator.operator2Nodeinfra, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator3CP0XStakrspace, proofAndPointsByOperator.operator3CP0XStakrspace, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator4HashkeyCloud, proofAndPointsByOperator.operator4HashkeyCloud, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator5Alchemy, proofAndPointsByOperator.operator5Alchemy, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator6Opslayer, proofAndPointsByOperator.operator6Opslayer, eraIndex, totalPoints
        );
        _claimAndCheckRewardsForStaker(
            operators.operator7TanssiFoundation,
            proofAndPointsByOperator.operator7TanssiFoundation,
            eraIndex,
            totalPoints
        );
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
            uint256 newStakerRewardsBalances = rewardsToken.balanceOf(vaultToStakerRewards[operator.vaults[i]]);
            uint256 actualRewards = newStakerRewardsBalances - stakerRewardsBalancesBefore[i];
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
        (proofAndPointsByOperator.operator2Nodeinfra.proof, proofAndPointsByOperator.operator2Nodeinfra.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Nodeinfra");
        (
            proofAndPointsByOperator.operator3CP0XStakrspace.proof,
            proofAndPointsByOperator.operator3CP0XStakrspace.points
        ) = _loadRewardsProofAndPointsForOperator(caseIndex, "CP0X");
        (proofAndPointsByOperator.operator4HashkeyCloud.proof, proofAndPointsByOperator.operator4HashkeyCloud.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "HashkeyCloud");
        (proofAndPointsByOperator.operator5Alchemy.proof, proofAndPointsByOperator.operator5Alchemy.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Alchemy");
        (proofAndPointsByOperator.operator6Opslayer.proof, proofAndPointsByOperator.operator6Opslayer.points) =
            _loadRewardsProofAndPointsForOperator(caseIndex, "Opslayer");
        (
            proofAndPointsByOperator.operator7TanssiFoundation.proof,
            proofAndPointsByOperator.operator7TanssiFoundation.points
        ) = _loadRewardsProofAndPointsForOperator(caseIndex, "TanssiFoundation");

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

        vm.warp(vm.getBlockTimestamp() + VETO_DURATION + 1);

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
