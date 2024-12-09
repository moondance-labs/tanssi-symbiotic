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
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {MetadataService} from "@symbiotic/contracts/service/MetadataService.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {IDefaultCollateral} from "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateral.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";

import {Middleware} from "../../src/middleware/Middleware.sol";
import {SimpleKeyRegistry32} from "../../src/libraries/SimpleKeyRegistry32.sol";

import {Token} from "../mocks/Token.sol";
import {DeployTanssiEcosystem} from "../../script/DeployTanssiEcosystem.s.sol";
import {DeployVault} from "../../script/DeployVault.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

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

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    address public owner = vm.addr(ownerPrivateKey);
    address tanssi = owner;

    address public operator = makeAddr("operator");
    address public operator2 = makeAddr("operator2");
    address public operator3 = makeAddr("operator3");
    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");

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

    Middleware public middleware;
    VaultFactory public vaultFactory;
    OperatorRegistry public operatorRegistry;
    NetworkRegistry public networkRegistry;
    OptInService public operatorVaultOptInService;
    OptInService public operatorNetworkOptInService;
    VetoSlasher public vetoSlasher;

    NetworkMiddlewareService public networkMiddlewareService;
    IDefaultCollateral public stETH;

    VaultAddresses public vaultAddresses;
    Vault vault;
    Vault vaultSlashable;
    Vault vaultVetoed;

    function setUp() public {
        vm.allowCheatcodes(address(0x6B5CF024365D5d5d0786673780CA7E3F07f85B63)); //DeployVault contract
        DeployTanssiEcosystem deployTanssi = new DeployTanssiEcosystem();
        HelperConfig helperConfig = new HelperConfig();

        (
            ,
            address operatorRegistryAddress,
            address networkRegistryAddress,
            address vaultRegistryAddress,
            address operatorNetworkOptInServiceAddress,
            address operatorVaultOptInServiceAddress,
            address networkMiddlewareServiceAddress,
            address defaultCollateralFactoryAddress,
        ) = helperConfig.activeNetworkConfig();

        deployTanssi.deployTanssiEcosystem(helperConfig);
        (
            vaultAddresses.vault,
            vaultAddresses.delegator,
            vaultAddresses.slasher,
            vaultAddresses.vaultSlashable,
            vaultAddresses.delegatorSlashable,
            vaultAddresses.slasherSlashable,
            vaultAddresses.vaultVetoed,
            vaultAddresses.delegatorVetoed,
            vaultAddresses.slasherVetoed
        ) = deployTanssi.vaultAddresses();
        stETH = IDefaultCollateral(deployTanssi.defaultCollateralAddress());
        deal(address(stETH), operator, OPERATOR_INITIAL_BALANCE);
        deal(address(stETH), operator2, OPERATOR_INITIAL_BALANCE);
        deal(address(stETH), operator3, OPERATOR_INITIAL_BALANCE);

        networkMiddlewareService = NetworkMiddlewareService(networkMiddlewareServiceAddress);
        vaultFactory = VaultFactory(vaultRegistryAddress);
        networkRegistry = NetworkRegistry(networkRegistryAddress);
        operatorRegistry = OperatorRegistry(operatorRegistryAddress);
        operatorNetworkOptInService = OptInService(operatorNetworkOptInServiceAddress);
        operatorVaultOptInService = OptInService(operatorVaultOptInServiceAddress);

        middleware = deployTanssi.middleware();

        vetoSlasher = VetoSlasher(vaultAddresses.slasherVetoed);

        vault = Vault(vaultAddresses.vault);
        vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        vaultVetoed = Vault(vaultAddresses.vaultVetoed);

        _registerOperator(operator, tanssi, vaultAddresses.vault);
        _registerOperator(operator3, tanssi, vaultAddresses.vaultSlashable);
        _registerOperator(operator2, tanssi, vaultAddresses.vaultVetoed);

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);

        _setLimitForNetworkAndOperators(tanssi);

        vm.startPrank(tanssi);
        vetoSlasher.setResolver(0, resolver1, hex"");
        vetoSlasher.setResolver(0, resolver2, hex"");

        vm.startPrank(operator);
        _depositToVault(vault, operator, 100 ether, stETH);

        vm.startPrank(operator2);
        operatorVaultOptInService.optIn(address(vaultSlashable));
        _depositToVault(vaultSlashable, operator2, 100 ether, stETH);
        _depositToVault(vaultVetoed, operator2, 100 ether, stETH);
        vm.stopPrank();

        vm.startPrank(operator3);
        operatorVaultOptInService.optIn(address(vault));
        operatorVaultOptInService.optIn(address(vaultVetoed));
        _depositToVault(vault, operator3, 100 ether, stETH);
        _depositToVault(vaultSlashable, operator3, 100 ether, stETH);
        _depositToVault(vaultVetoed, operator3, 100 ether, stETH);

        vm.stopPrank();
    }

    function _depositToVault(Vault _vault, address _operator, uint256 _amount, IERC20 collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        vm.startPrank(_owner);
        // middleware.registerVault(vaultAddresses.vault);
        // middleware.registerVault(vaultAddresses.vaultSlashable);
        // middleware.registerVault(vaultAddresses.vaultVetoed);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerOperator(operator2, OPERATOR2_KEY);
        middleware.registerOperator(operator3, OPERATOR3_KEY);
        vm.stopPrank();
    }

    function _registerOperator(address _operator, address _network, address _vault) public {
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
        assertEq(middleware.i_network(), tanssi);
        assertEq(middleware.i_operatorRegistry(), address(operatorRegistry));
        assertEq(middleware.i_vaultRegistry(), address(vaultFactory));
        assertEq(middleware.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(middleware.i_slashingWindow(), SLASHING_WINDOW);
        assertEq(middleware.s_subnetworksCount(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public view {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);
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
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        assertEq(validators.length, 3);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);
        assertEq(operatorVaultPairs.length, 3);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[1].operator, operator2);
        assertEq(operatorVaultPairs[2].operator, operator3);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
        assertEq(operatorVaultPairs[1].vaults.length, 2);
        assertEq(operatorVaultPairs[2].vaults.length, 3);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch = middleware.getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].stake, validatorsPreviousEpoch[0].stake);
        assertEq(validators[1].stake, validatorsPreviousEpoch[1].stake);
        assertEq(validators[2].stake, validatorsPreviousEpoch[2].stake);
        assertEq(validators[0].key, validatorsPreviousEpoch[0].key);
        assertEq(validators[1].key, validatorsPreviousEpoch[1].key);
        assertEq(validators[2].key, validatorsPreviousEpoch[2].key);
    }

    function testWithdraw() public {
        uint256 currentEpoch = vaultSlashable.currentEpoch();

        vm.prank(operator2);
        vaultSlashable.withdraw(operator2, DEFAULT_WITHDRAW_AMOUNT);

        vm.warp(block.timestamp + VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = vaultSlashable.currentEpoch();

        vm.prank(operator2);
        vaultSlashable.claim(operator2, currentEpoch - 1);
        assertEq(stETH.balanceOf(operator2), OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE * 2 + DEFAULT_WITHDRAW_AMOUNT);
    }

    function testSlashingOnOperator2AndVetoingSlash() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);
        //We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;

        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, 30 ether);

        vm.prank(resolver1);
        vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;
        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, 30 ether);

        vm.warp(block.timestamp + VETO_DURATION);
        vm.prank(address(middleware));
        vetoSlasher.executeSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        activeStakeInVetoed = vaultVetoed.activeStake();
        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator3AndVetoingSlash() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake,) = _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other (non slashable) vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator3 since it's the only one that should be slashed. As a side effect operator2 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable3 = (SLASH_AMOUNT * remainingOperator3Stake) / totalOperator3Stake;

        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, 30 ether);

        vm.prank(resolver1);
        vetoSlasher.vetoSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable3);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable3);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingOnOperator3AndExecuteSlashOnVetoVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake,) = _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other (non slashable) vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator3 since it's the only one that should be slashed. As a side effect operator2 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable3 =
            (SLASH_AMOUNT * remainingOperator3Stake) / (totalOperator3Stake + remainingOperator3Stake);

        vm.prank(owner);
        middleware.slash(currentEpoch, operator3, 30 ether);

        vm.warp(block.timestamp + VETO_DURATION);
        vm.prank(address(middleware));
        vetoSlasher.executeSlash(0, hex"");
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        activeStakeInVetoed = vaultVetoed.activeStake();
        (uint256 totalOperator2StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, slashAmountSlashable3);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable3);
        assertEq(validators[1].stake, totalOperator2StakeAfter);
        assertEq(validators[2].stake, totalOperator3StakeAfter);
    }

    function testSlashingAndPausingVault() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        vm.prank(owner);
        middleware.pauseVault(vaultAddresses.vaultSlashable);

        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, 30 ether);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        assertEq(validators[1].stake, OPERATOR_STAKE * 2);
        assertEq(validators[2].stake, OPERATOR_STAKE * 2 + remainingOperator2Stake);
    }

    function testSlashingAndPausingOperator() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        uint256 slashAmountSlashable = (SLASH_AMOUNT * remainingOperator2Stake) / totalOperator2Stake;

        vm.prank(owner);
        middleware.pauseOperator(operator2);

        vm.prank(owner);
        //! Why this slash should anyway go through if operator was paused? Shouldn't it revert?
        middleware.slash(currentEpoch, operator2, 30 ether);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        (uint256 totalOperator3StakeAfter,) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2 * 2, activeStakeInVetoed, slashAmountSlashable);
        assertEq(validators[1].stake, totalOperator3StakeAfter);
    }

    function testOperatorsOnlyInTanssiNetwork() public {
        address operator4 = makeAddr("operator4");
        address network2 = makeAddr("network2");

        bytes32 OPERATOR4_KEY = bytes32(uint256(4));
        deal(address(stETH), operator4, OPERATOR_INITIAL_BALANCE);

        //Middleware 2 Deployment
        vm.startPrank(network2);
        networkRegistry.registerNetwork();
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);

        vm.startPrank(owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            network2.subnetwork(0), operator4, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(
            network2.subnetwork(0), OPERATOR_NETWORK_LIMIT
        );

        // Operator4 registration and network configuration
        _registerOperator(operator4, network2, address(vault));
        vm.startPrank(network2);
        Middleware middleware2 = new Middleware(
            network2,
            address(operatorRegistry),
            address(vaultFactory),
            address(operatorNetworkOptInService),
            network2,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        networkMiddlewareService.setMiddleware(address(middleware2));
        middleware2.registerVault(address(vault));
        middleware2.registerOperator(operator4, OPERATOR4_KEY);

        vm.stopPrank();
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 middleware2CurrentEpoch = middleware2.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operator2VaultPairs =
            middleware2.getOperatorVaultPairs(middleware2CurrentEpoch);
        assertEq(operator2VaultPairs.length, 1);
        assertEq(operator2VaultPairs[0].operator, operator4);
        assertEq(operator2VaultPairs[0].vaults.length, 1);
        uint48 middlewareCurrentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            middleware.getOperatorVaultPairs(middlewareCurrentEpoch);
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            assert(operatorVaultPairs[i].operator != operator4);
        }
    }
}
