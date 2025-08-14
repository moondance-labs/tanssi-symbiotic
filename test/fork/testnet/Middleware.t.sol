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
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
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
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 2 days;
    uint48 public constant VETO_DURATION = 1 days;
    uint256 public constant SLASH_AMOUNT = 30 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant SLASHING_FRACTION = PARTS_PER_BILLION / 10; // 10%
    uint8 public constant ORACLE_DECIMALS = 1;
    int256 public constant ORACLE_CONVERSION_TOKEN = 20_000;

    // This needs to be read from live contracts
    uint256 public vaultShares;
    uint256 public operatorShares;
    uint256 public totalVaultPower; // By shares. Each operator participates gets 1/3 of the total power
    uint256 public operatorStake;

    address public admin;
    address public tanssi;
    address public operator;
    address public gateway;

    address public oracle = makeAddr("oracle");

    HelperConfig helperConfig;
    HelperConfig.VaultData vaultData;
    HelperConfig.OperatorData operatorData;
    IVault vault;
    Middleware middleware;
    ODefaultOperatorRewards operatorRewards;
    IERC20 stETH;

    function setUp() public {
        _loadBaseInfrastructure();

        vm.startPrank(admin);
        middleware.setCollateralToOracle(address(stETH), oracle);
        vm.mockCall(
            oracle,
            abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),
            abi.encode(uint80(0), uint256(ORACLE_CONVERSION_TOKEN), uint256(0), uint256(0), uint80(0))
        );
        vm.mockCall(
            oracle, abi.encodeWithSelector(AggregatorV3Interface.decimals.selector), abi.encode(uint8(ORACLE_DECIMALS))
        );
        vm.stopPrank();
    }

    function _loadBaseInfrastructure() private {
        helperConfig = new HelperConfig();
        address stEth;
        address middlewareAddress;
        address operatorRewardsAddress;

        (admin, tanssi, gateway,, middlewareAddress, operatorRewardsAddress,) = helperConfig.activeEntities();
        HelperConfig.CollateralData memory stEthConfig;
        (stEthConfig,,,,,,) = helperConfig.activeTokensConfig();
        stEth = stEthConfig.collateral;
        (,,,,,,,,, vaultData) = helperConfig.activeVaultsConfigA();
        (,,,,,,,,,, operatorData) = helperConfig.activeOperatorConfig();
        operator = operatorData.evmAddress;

        middleware = Middleware(middlewareAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        stETH = IERC20(stEth);
        vault = IVault(vaultData.vault);

        operatorStake = vault.activeBalanceOf(operator);
        operatorShares = vault.activeSharesOf(operator);
        vaultShares = vault.activeShares();
    }

    function _depositToVault(IVault _vault, address _operator, uint256 _amount, IERC20 collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
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

    /**
     * @param operatorStake_ The total stake of all operator vaults using NetworkRestake delegation
     * @param amountSlashed The amount slashed from the operator
     * @return totalOperatorPower
     */
    function _calculateOperatorPower(
        uint256 operatorStake_,
        uint256 amountSlashed
    ) public view returns (uint256 totalOperatorPower) {
        totalOperatorPower = operatorShares.mulDiv(operatorStake_ - amountSlashed, vaultShares).mulDiv(
            uint256(ORACLE_CONVERSION_TOKEN), 10 ** ORACLE_DECIMALS
        );
    }

    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        (, address operatorRegistryAddress,, address vaultFactoryAddress,,,,,) = helperConfig.activeNetworkConfig();

        assertEq(OBaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
        assertEq(OBaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY(), operatorRegistryAddress);
        assertEq(OBaseMiddlewareReader(address(middleware)).VAULT_REGISTRY(), vaultFactoryAddress);
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(OBaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), SLASHING_WINDOW);
        assertEq(OBaseMiddlewareReader(address(middleware)).subnetworksLength(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
    }

    function testOperatorsAreRegisteredAfterOneEpoch() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(previousEpoch);

        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + 1);
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(previousEpoch);
        assertEq(validators.length, validatorsPreviousEpoch.length);
        assertEq(validators[0].power, validatorsPreviousEpoch[0].power);
        assertEq(validators[0].key, validatorsPreviousEpoch[0].key);
    }

    function testWithdraw() public {
        uint256 currentEpoch = vault.currentEpoch();
        uint256 withdrawAmount = operatorStake / 10;
        uint256 operatorBalanceBefore = stETH.balanceOf(operator);

        vm.prank(operator);
        vault.withdraw(operator, withdrawAmount);

        vm.warp(vm.getBlockTimestamp() + VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = vault.currentEpoch();

        vm.prank(operator);
        vault.claim(operator, currentEpoch - 1);
        assertApproxEqAbs(stETH.balanceOf(operator), operatorBalanceBefore + withdrawAmount, 1);
    }

    function testOperatorPower() public {
        (, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower) = _prepareSlashingTest();

        assertApproxEqAbs(validators[0].power, totalOperatorPower, 1);
    }

    function testSlashingOperator() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower) =
            _prepareSlashingTest();

        assertEq(validators.length, 1);
        assertEq(validators[0].power, totalOperatorPower);
        assertEq(validators[0].key, operatorData.operatorKey);

        vm.prank(gateway);
        middleware.slash(currentEpoch, operatorData.operatorKey, SLASHING_FRACTION);

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        uint256 slashedAmount = operatorStake.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);
        totalOperatorPower = _calculateOperatorPower(operatorStake, slashedAmount);

        assertEq(validators.length, 1);
        assertEq(validators[0].power, totalOperatorPower);
        assertEq(validators[0].key, operatorData.operatorKey);
    }

    function testSlashingAndPausingVault() public {
        (uint48 currentEpoch,,) = _prepareSlashingTest();

        vm.prank(admin);
        middleware.pauseSharedVault(vaultData.vault);

        vm.prank(gateway);
        middleware.slash(currentEpoch, operatorData.operatorKey, SLASHING_FRACTION);

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        // Vault is paused so there should be none
        assertEq(validators.length, 0);

        // Power should have changed since the vault and operator were active at the start of the epoch where the slash was applied
        uint256 newOperatorStake = IBaseDelegator(vaultData.delegator).stake(tanssi.subnetwork(0), operator);
        uint256 newOperatorPower = middleware.stakeToPower(vaultData.vault, newOperatorStake);
        uint256 slashedAmount = operatorStake.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);
        uint256 expectedOperatorPower = _calculateOperatorPower(operatorStake, slashedAmount);

        assertEq(newOperatorPower, expectedOperatorPower);
    }

    function testSlashingAndPausingOperator() public {
        (uint48 currentEpoch,,) = _prepareSlashingTest();

        vm.prank(admin);
        middleware.pauseOperator(operator);

        vm.prank(gateway);
        middleware.slash(currentEpoch, operatorData.operatorKey, SLASHING_FRACTION);

        vm.warp(vm.getBlockTimestamp() + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        // Operator is paused so there should be none
        assertEq(validators.length, 0);

        // Power should not have changed since the operator is paused
        uint256 newOperatorStake = IBaseDelegator(vaultData.delegator).stake(tanssi.subnetwork(0), operator);
        uint256 newOperatorPower = middleware.stakeToPower(vaultData.vault, newOperatorStake);
        uint256 slashedAmount = operatorStake.mulDiv(SLASHING_FRACTION, PARTS_PER_BILLION);
        uint256 expectedOperatorPower = _calculateOperatorPower(operatorStake, slashedAmount);

        assertEq(newOperatorPower, expectedOperatorPower);
    }

    function _prepareSlashingTest()
        public
        returns (uint48 currentEpoch, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower)
    {
        vm.warp(vm.getBlockTimestamp() + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        currentEpoch = middleware.getCurrentEpoch();

        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        totalOperatorPower = _calculateOperatorPower(operatorStake, 0);
    }
}
