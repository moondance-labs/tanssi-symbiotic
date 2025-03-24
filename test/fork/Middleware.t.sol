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
import {BaseMiddlewareReader} from "@symbiotic-middleware/middleware/BaseMiddlewareReader.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
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
    uint256 public constant OPERATOR_STAKE = 100 ether;
    uint256 public constant DEFAULT_WITHDRAW_AMOUNT = 30 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant OPERATOR2_KEY = bytes32(uint256(2));
    bytes32 public constant OPERATOR3_KEY = bytes32(uint256(3));
    uint48 public constant OPERATOR_SHARE = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;
    uint256 public constant TOTAL_NETWORK_SHARES = 3;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;

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
        _depositToVault(ecosystemEntities.vault, operator, 100 ether, ecosystemEntities.stETH);
        vm.stopPrank();

        {
            // Scoped to help with stack depth
            vm.startPrank(operator2);
            operatorVaultOptInService.optIn(address(ecosystemEntities.vaultSlashable));
            _depositToVault(ecosystemEntities.vaultSlashable, operator2, 100 ether, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultVetoed, operator2, 100 ether, ecosystemEntities.stETH);
            vm.stopPrank();
        }

        {
            // Scoped to help with stack depth
            vm.startPrank(operator3);
            operatorVaultOptInService.optIn(address(ecosystemEntities.vault));
            operatorVaultOptInService.optIn(address(ecosystemEntities.vaultVetoed));
            _depositToVault(ecosystemEntities.vault, operator3, 100 ether, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultSlashable, operator3, 100 ether, ecosystemEntities.stETH);
            _depositToVault(ecosystemEntities.vaultVetoed, operator3, 100 ether, ecosystemEntities.stETH);
            vm.stopPrank();
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
            tanssi.subnetwork(0), operator2, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, OPERATOR_SHARE
        );

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, OPERATOR_SHARE
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
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator, OPERATOR_NETWORK_LIMIT
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, OPERATOR_NETWORK_LIMIT
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, OPERATOR_NETWORK_LIMIT
        );
        vm.stopPrank();
    }

    /**
     * @param _operatorStake the total stake of the operator in each vault he is registered
     * @param _activeStake the active stake of vault's FullRestake delegated
     * @param _amountSlashed the amount slashed from the operator
     * @return totalOperatorStake
     * @return remainingOperatorStake
     */
    function _calculateTotalOperatorStake(
        uint256 _operatorStake,
        uint256 _activeStake,
        uint256 _amountSlashed
    ) public pure returns (uint256 totalOperatorStake, uint256 remainingOperatorStake) {
        remainingOperatorStake =
            _calculateRemainingStake(OPERATOR_SHARE, TOTAL_NETWORK_SHARES, _operatorStake - _amountSlashed);
        totalOperatorStake = remainingOperatorStake + _activeStake;
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

        assertEq(BaseMiddlewareReader(address(ecosystemEntities.middleware)).NETWORK(), tanssi);
        assertEq(
            BaseMiddlewareReader(address(ecosystemEntities.middleware)).OPERATOR_REGISTRY(), operatorRegistryAddress
        );
        assertEq(BaseMiddlewareReader(address(ecosystemEntities.middleware)).VAULT_REGISTRY(), vaultFactoryAddress);
        assertEq(EpochCapture(address(ecosystemEntities.middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(BaseMiddlewareReader(address(ecosystemEntities.middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(BaseMiddlewareReader(address(ecosystemEntities.middleware)).subnetworksLength(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            ecosystemEntities.middleware.getOperatorVaultPairs(currentEpoch);
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
        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        assertEq(validators.length, 3);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            ecosystemEntities.middleware.getOperatorVaultPairs(currentEpoch);
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
            ecosystemEntities.middleware.getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].stake, validatorsPreviousEpoch[0].stake);
        assertEq(validators[1].stake, validatorsPreviousEpoch[1].stake);
        assertEq(validators[2].stake, validatorsPreviousEpoch[2].stake);
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

    function testSlashingOnOperator2AndVetoingSlash() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);
        //We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;
        uint256 amountToSlash = 30 ether;
        uint256 slashingFraction = amountToSlash.mulDiv(PARTS_PER_BILLION, totalOperator2Stake);

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);

        vm.prank(resolver1);
        ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;
        uint256 amountToSlash = 30 ether;
        uint256 slashingFraction = amountToSlash.mulDiv(PARTS_PER_BILLION, totalOperator2Stake);
        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);

        vm.warp(block.timestamp + VETO_DURATION);
        vm.prank(address(ecosystemEntities.middleware));
        ecosystemEntities.vetoSlasher.executeSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();
        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator3AndVetoingSlash() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake,) = _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other (non slashable) vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator3 since it's the only one that should be slashed. As a side effect operator2 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable3 = (SLASH_AMOUNT * remainingOperator3Stake) / totalOperator3Stake;
        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(PARTS_PER_BILLION, totalOperator3Stake);

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);

        vm.prank(resolver1);
        ecosystemEntities.vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable3);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable3);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator3AndExecuteSlashOnVetoVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake,) = _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other (non slashable) vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator3 since it's the only one that should be slashed. As a side effect operator2 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable3 =
            (SLASH_AMOUNT * remainingOperator3Stake) / (totalOperator3Stake + remainingOperator3Stake);

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage

        uint256 slashingFraction =
            slashedAmount.mulDiv(PARTS_PER_BILLION, totalOperator3Stake + remainingOperator3Stake);

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR3_KEY, slashingFraction);

        vm.warp(block.timestamp + VETO_DURATION);
        vm.prank(address(ecosystemEntities.middleware));
        ecosystemEntities.vetoSlasher.executeSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();
        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable3);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable3);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingAndPausingVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(PARTS_PER_BILLION, totalOperator2Stake);

        vm.prank(owner);
        ecosystemEntities.middleware.pauseSharedVault(vaultAddresses.vaultSlashable);

        vm.prank(gateway);
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        assertEq(validators[1].stake, OPERATOR_STAKE * 2);
        assertEq(validators[2].stake, OPERATOR_STAKE * 2 + remainingOperator2Stake);
    }

    function testSlashingAndPausingOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = ecosystemEntities.middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = ecosystemEntities.middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = ecosystemEntities.vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(PARTS_PER_BILLION, totalOperator2Stake);

        vm.prank(owner);
        ecosystemEntities.middleware.pauseOperator(operator2);

        vm.prank(gateway);
        //! Why this slash should anyway go through if operator was paused? Shouldn't it revert?
        ecosystemEntities.middleware.slash(currentEpoch, OPERATOR2_KEY, slashingFraction);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = ecosystemEntities.middleware.getCurrentEpoch();
        validators = ecosystemEntities.middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator3StakeAfter);
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
        address readHelper = address(new BaseMiddlewareReader());
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: network2,
            operatorRegistry: operatorRegistryAddress,
            vaultRegistry: vaultFactoryAddress,
            operatorNetworkOptIn: operatorNetworkOptInServiceAddress,
            owner: network2,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: readHelper,
            forwarder: address(0)
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
            ecosystemEntities.middleware.getOperatorVaultPairs(middlewareCurrentEpoch);

        uint48 middleware2CurrentEpoch = middleware2.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operator2VaultPairs =
            middleware2.getOperatorVaultPairs(middleware2CurrentEpoch);

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
        DeployRewards deployRewards = new DeployRewards(true);

        address operatorRewardsAddress =
            deployRewards.deployOperatorRewardsContract(network, networkMiddlewareServiceAddress, 5000, owner);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            vaultFactoryAddress, networkMiddlewareServiceAddress, operatorRewardsAddress, owner
        );

        middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
    }
}
