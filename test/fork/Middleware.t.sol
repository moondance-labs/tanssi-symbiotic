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
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
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
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant VETO_DURATION = 1 days;
    uint256 public constant SLASH_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_STAKE = 90 ether;
    uint256 public constant DEFAULT_WITHDRAW_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant OPERATOR2_KEY = bytes32(uint256(2));
    bytes32 public constant OPERATOR3_KEY = bytes32(uint256(3));
    uint48 public constant OPERATOR_SHARE = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;
    uint256 public constant TOTAL_NETWORK_SHARES = 2;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 10; // 10%
    uint8 public constant ORACLE_DECIMALS = 3;
    int256 public constant ORACLE_CONVERSION_TOKEN = 2000;

    uint256 public totalFullRestakePower; // Each operator participates with 100% of all operators stake
    uint256 public totalPowerVault; // By shares. Each operator participates gets 1/3 of the total power
    uint256 public totalPowerVaultSlashable; // By shares. Each operator participates gets 1/3 of the total power

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);
    address tanssi = owner;

    address public operator = makeAddr("operator");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");
    address public gateway = makeAddr("gateway");
    address public oracle = makeAddr("oracle");
    address public operatorRewardsAddress;

    HelperConfig helperConfig;

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

    struct EcosystemEntity {
        Middleware middleware;
        IVetoSlasher vetoSlasher;
        IVault vault;
        IVault vaultSlashable;
        IVault vaultVetoed;
        IDefaultCollateral stETH;
    }

    VaultAddresses public vaultAddresses;
    EcosystemEntity public ecosystemEntities;

    function setUp() public {
        _deployBaseInfrastructure();
        _setupOperators();

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);
        _setLimitForNetworkAndOperators(tanssi);

        vm.startPrank(tanssi);
        ecosystemEntities.vetoSlasher.setResolver(0, resolver1, hex"");
        ecosystemEntities.vetoSlasher.setResolver(0, resolver2, hex"");
        ecosystemEntities.middleware.setGateway(gateway);
        ecosystemEntities.middleware.setCollateralToOracle(address(ecosystemEntities.stETH), oracle);
        vm.stopPrank();

        _handleDeposits();
    }

    function _deployBaseInfrastructure() private {
        vm.allowCheatcodes(address(0x6B5CF024365D5d5d0786673780CA7E3F07f85B63));
        DeployTanssiEcosystem deployTanssi = new DeployTanssiEcosystem();
        helperConfig = new HelperConfig();
        deployTanssi.deployTanssiEcosystem(helperConfig);

        address defaultCollateralAddress;
        (ecosystemEntities.middleware,, defaultCollateralAddress) = deployTanssi.ecosystemEntities();
        ecosystemEntities.stETH = IDefaultCollateral(defaultCollateralAddress);

        _setVaultAddresses(deployTanssi);
        _initializeVaults();
    }

    function _setupOperators() private {
        deal(address(ecosystemEntities.stETH), operator, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.stETH), operator2, OPERATOR_INITIAL_BALANCE);
        deal(address(ecosystemEntities.stETH), operator3, OPERATOR_INITIAL_BALANCE);

        _registerOperator(operator, tanssi, vaultAddresses.vault);
        _registerOperator(operator3, tanssi, vaultAddresses.vaultSlashable);
        _registerOperator(operator2, tanssi, vaultAddresses.vaultVetoed);
    }

    function _initializeVaults() private {
        ecosystemEntities.vault = IVault(vaultAddresses.vault);
        ecosystemEntities.vaultSlashable = IVault(vaultAddresses.vaultSlashable);
        ecosystemEntities.vaultVetoed = IVault(vaultAddresses.vaultVetoed);
        ecosystemEntities.vetoSlasher = IVetoSlasher(vaultAddresses.slasherVetoed);
    }

    struct VaultGroup {
        address vault;
        address delegator;
        address slasher;
    }

    function _setVaultAddresses(
        DeployTanssiEcosystem deployTanssi
    ) private {
        {
            VaultGroup memory baseVault;
            VaultGroup memory slashableVault;

            (
                baseVault.vault,
                baseVault.delegator,
                baseVault.slasher,
                slashableVault.vault,
                slashableVault.delegator,
                slashableVault.slasher,
                vaultAddresses.vaultVetoed,
                vaultAddresses.delegatorVetoed,
                vaultAddresses.slasherVetoed
            ) = deployTanssi.vaultAddresses();

            _setBaseVault(baseVault);
            _setSlashableVault(slashableVault);
        }
    }

    function _setBaseVault(
        VaultGroup memory baseVault
    ) private {
        vaultAddresses.vault = baseVault.vault;
        vaultAddresses.delegator = baseVault.delegator;
        vaultAddresses.slasher = baseVault.slasher;
    }

    function _setSlashableVault(
        VaultGroup memory slashableVault
    ) private {
        vaultAddresses.vaultSlashable = slashableVault.vault;
        vaultAddresses.delegatorSlashable = slashableVault.delegator;
        vaultAddresses.slasherSlashable = slashableVault.slasher;
    }

    function _handleDeposits() private {
        (,,,,, address operatorVaultOptInServiceAddress,,,,) = helperConfig.activeNetworkConfig();

        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);

        vm.startPrank(operator);
        _depositToVault(ecosystemEntities.vault, operator, OPERATOR_STAKE, ecosystemEntities.stETH);
        vm.stopPrank();

        {
            // Scoped to help with stack depth
            vm.startPrank(operator2);
            operatorVaultOptInService.optIn(address(ecosystemEntities.vaultSlashable));
            _depositToVault(ecosystemEntities.vaultSlashable, operator2, OPERATOR_STAKE, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultVetoed, operator2, OPERATOR_STAKE, ecosystemEntities.stETH);
            vm.stopPrank();
        }

        {
            // Scoped to help with stack depth
            vm.startPrank(operator3);
            operatorVaultOptInService.optIn(address(ecosystemEntities.vault));
            operatorVaultOptInService.optIn(address(ecosystemEntities.vaultVetoed));
            _depositToVault(ecosystemEntities.vault, operator3, OPERATOR_STAKE, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultSlashable, operator3, OPERATOR_STAKE, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultVetoed, operator3, OPERATOR_STAKE, ecosystemEntities.stETH);
            vm.stopPrank();
        }

        {
            totalFullRestakePower = (OPERATOR_STAKE * uint256(ORACLE_CONVERSION_TOKEN)) / 10 ** ORACLE_DECIMALS;

            totalPowerVault = (OPERATOR_STAKE * 2 * uint256(ORACLE_CONVERSION_TOKEN)) / 10 ** ORACLE_DECIMALS;
            totalPowerVaultSlashable = (OPERATOR_STAKE * 2 * uint256(ORACLE_CONVERSION_TOKEN)) / 10 ** ORACLE_DECIMALS;
        }
    }

    function _depositToVault(IVault _vault, address _operator, uint256 _amount, IERC20 collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        vm.startPrank(_owner);
        // middleware.registerSharedVault(vaultAddresses.vault);
        // middleware.registerSharedVault(vaultAddresses.vaultSlashable);
        // middleware.registerSharedVault(vaultAddresses.vaultVetoed);
        ecosystemEntities.middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator2, abi.encode(OPERATOR2_KEY), address(0));
        ecosystemEntities.middleware.registerOperator(operator3, abi.encode(OPERATOR3_KEY), address(0));
        vm.stopPrank();
    }

    function _registerOperator(address _operator, address _network, address _vault) public {
        (
            ,
            address operatorRegistryAddress,
            ,
            ,
            address operatorNetworkOptInServiceAddress,
            address operatorVaultOptInServiceAddress,
            ,
            ,
            ,
        ) = helperConfig.activeNetworkConfig();

        IOperatorRegistry operatorRegistry = IOperatorRegistry(operatorRegistryAddress);
        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);
        IOptInService operatorNetworkOptInService = IOptInService(operatorNetworkOptInServiceAddress);

        vm.startPrank(_operator);
        operatorRegistry.registerOperator();
        operatorVaultOptInService.optIn(address(_vault));
        operatorNetworkOptInService.optIn(_network);
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

    function _setLimitForNetworkAndOperators(
        address _owner
    ) public {
        vm.startPrank(_owner);
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, OPERATOR_STAKE
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, OPERATOR_STAKE
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
        (, address operatorRegistryAddress,, address vaultFactoryAddress,,,,,,) = helperConfig.activeNetworkConfig();

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
        assertEq(operatorVaultPairs.length, 3);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[1].vaults.length, 2);
        assertEq(operatorVaultPairs[2].vaults.length, 3);
    }

    function testOperatorsAreRegisteredAfterOneEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);
        assertEq(validators.length, 3);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 3);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[1].vaults.length, 2);
        assertEq(operatorVaultPairs[2].vaults.length, 3);
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

    function testWithdraw() public {
        uint256 currentEpoch = ecosystemEntities.vaultSlashable.currentEpoch();

        vm.prank(operator2);
        ecosystemEntities.vaultSlashable.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(block.timestamp + VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = ecosystemEntities.vaultSlashable.currentEpoch();

        vm.prank(operator2);
        ecosystemEntities.vaultSlashable.claim(operator2, currentEpoch - 1);
        assertEq(
            ecosystemEntities.stETH.balanceOf(operator2),
            OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE * 2 + DEFAULT_WITHDRAW_AMOUNT
        );
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
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.prank(resolver1);
        ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + VETO_DURATION);
        ecosystemEntities.middleware.executeSlash(address(ecosystemEntities.vaultVetoed), 0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

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
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

        vm.prank(resolver1);
        ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

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
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR3_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + VETO_DURATION);
        ecosystemEntities.middleware.executeSlash(address(ecosystemEntities.vaultVetoed), 0, hex"");

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingAndPausingVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,,,,) = _prepareSlashingTest();

        vm.prank(owner);
        ecosystemEntities.middleware.pauseSharedVault(vaultAddresses.vaultSlashable);

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator2PowerAfter,) = _calculateOperatorPower(0, totalFullRestakePower, 0);
        (uint256 totalOperator3PowerAfter,) = _calculateOperatorPower(totalPowerVault, totalFullRestakePower, 0);

        assertEq(validators[1].power, totalOperator2PowerAfter);
        assertEq(validators[2].power, totalOperator3PowerAfter);
    }

    function testSlashingAndPausingOperator() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,, uint256 powerFromSharesOperator2,,) =
            _prepareSlashingTest();

        vm.prank(owner);
        ecosystemEntities.middleware.pauseOperator(operator2);

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashingPower = (SLASHING_FRACTION * powerFromSharesOperator2) / PARTS_PER_BILLION;

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(newEpoch);

        (uint256 totalOperator3PowerAfter,) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, slashingPower);
        // Index is 1 instead of 2 because operator2 was paused
        assertEq(validators[1].power, totalOperator3PowerAfter);
    }

    function testOperatorsOnlyInTanssiNetwork() public {
        (
            ,
            address operatorRegistryAddress,
            address networkRegistryAddress,
            address vaultFactoryAddress,
            address operatorNetworkOptInServiceAddress,
            ,
            address networkMiddlewareServiceAddress,
            ,
            ,
        ) = helperConfig.activeNetworkConfig();

        address operator4 = makeAddr("operator4");
        address network2 = makeAddr("network2");

        bytes32 OPERATOR4_KEY = bytes32(uint256(4));
        deal(address(ecosystemEntities.stETH), operator4, OPERATOR_INITIAL_BALANCE);

        //Middleware 2 Deployment
        vm.startPrank(network2);
        INetworkRegistry(networkRegistryAddress).registerNetwork();
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);

        vm.startPrank(owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            network2.subnetwork(0), operator4, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(
            network2.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );
        _registerOperator(operator4, network2, address(ecosystemEntities.vault));

        vm.startPrank(network2);

        Middleware _middlewareImpl = _getMiddlewareImpl(network2, vaultFactoryAddress, networkMiddlewareServiceAddress);
        Middleware middleware2 = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
        vm.startPrank(owner);
        ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware2));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware2));

        vm.startPrank(network2);
        address readHelper = address(new OBaseMiddlewareReader());
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: network2,
            operatorRegistry: operatorRegistryAddress,
            vaultRegistry: vaultFactoryAddress,
            operatorNetworkOptIn: operatorNetworkOptInServiceAddress,
            owner: network2,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper
        });
        middleware2.initialize(params);

        INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(address(middleware2));
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: network2,
            adminFeeClaimRoleHolder: network2,
            adminFeeSetRoleHolder: network2
        });
        middleware2.registerSharedVault(address(ecosystemEntities.vault), stakerRewardsParams);
        middleware2.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

        uint48 middlewareCurrentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getOperatorVaultPairs(middlewareCurrentEpoch);

        uint48 middleware2CurrentEpoch = middleware2.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operator2VaultPairs =
            OBaseMiddlewareReader(address(middleware2)).getOperatorVaultPairs(middleware2CurrentEpoch);

        assertEq(operator2VaultPairs.length, 1);
        assertEq(operator2VaultPairs[0].operator, operator4);
        assertEq(operator2VaultPairs[0].vaults.length, 1);

        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            assert(operatorVaultPairs[i].operator != operator4);
        }
    }

    function _getMiddlewareImpl(
        address network,
        address vaultFactoryAddress,
        address networkMiddlewareServiceAddress
    ) private returns (Middleware middlewareImpl) {
        DeployRewards deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);

        operatorRewardsAddress =
            deployRewards.deployOperatorRewardsContract(network, networkMiddlewareServiceAddress, 5000, owner);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            vaultFactoryAddress, networkMiddlewareServiceAddress, operatorRewardsAddress, owner
        );

        middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
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
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        validators = OBaseMiddlewareReader(address(ecosystemEntities.middleware)).getValidatorSet(currentEpoch);

        (totalOperator2Power, powerFromSharesOperator2) =
            _calculateOperatorPower(totalPowerVaultSlashable, totalFullRestakePower, 0);
        (totalOperator3Power, powerFromSharesOperator3) =
            _calculateOperatorPower(totalPowerVault + totalPowerVaultSlashable, totalFullRestakePower, 0);
    }
}
