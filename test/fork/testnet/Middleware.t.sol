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
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {Token} from "test/mocks/Token.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
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
    uint256 public operatorStake = 90 ether;
    uint256 public vaultShares;
    uint256 public operatorShares;
    uint256 public totalVaultPower; // By shares. Each operator participates gets 1/3 of the total power

    address public admin;
    address public tanssi;
    address public operator;
    address public gateway;

    address public oracle = makeAddr("oracle"); // TODO: We could actually get it from contract-addresses but it's not available through HelperConfig at the moment

    HelperConfig helperConfig;
    HelperConfig.VaultTrifecta vaultData;
    HelperConfig.OperatorData operatorData;
    IVault vault;
    Middleware middleware;
    ODefaultOperatorRewards operatorRewards;
    IDefaultCollateral stETH;

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
        (stEth,,,,,) = helperConfig.activeTokensConfig();
        (,,,,,,,,, vaultData) = helperConfig.activeVaultsConfigA();
        (,,,,,,,,,, operatorData) = helperConfig.activeOperatorConfig();
        operator = operatorData.evmAddress;

        middleware = Middleware(middlewareAddress);
        operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        stETH = IDefaultCollateral(stEth);
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
    ) public returns (uint256 totalOperatorPower) {
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
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
    }

    function testOperatorsAreRegisteredAfterOneEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.OperatorVaultPair[] memory operatorVaultPairs =
            OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(currentEpoch);

        assertEq(operatorVaultPairs.length, 1);
        assertEq(operatorVaultPairs[0].operator, operator);
        assertEq(operatorVaultPairs[0].vaults.length, 1);
    }

    function testOperatorsStakeIsTheSamePerEpoch() public {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        uint48 previousEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validatorsPreviousEpoch =
            OBaseMiddlewareReader(address(middleware)).getValidatorSet(previousEpoch);

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
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

        vm.warp(block.timestamp + VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = vault.currentEpoch();

        vm.prank(operator);
        vault.claim(operator, currentEpoch - 1);
        assertEq(stETH.balanceOf(operator), operatorBalanceBefore + withdrawAmount);
    }

    function testOperatorPower() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower) =
            _prepareSlashingTest();

        assertApproxEqAbs(validators[0].power, totalOperatorPower, 1);
    }

    function testSlashingAndPausingVault() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators,) = _prepareSlashingTest();

        vm.prank(admin);
        middleware.pauseSharedVault(vaultData.vault);

        vm.prank(gateway);
        middleware.slash(currentEpoch, operatorData.operatorKey, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);

        // Vault is paused so there should be none
        assertEq(validators.length, 0);
    }

    function testSlashingAndPausingOperator() public {
        (uint48 currentEpoch, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower) =
            _prepareSlashingTest();

        vm.prank(admin);
        middleware.pauseOperator(operator);

        // We calculate the amount slashable for only the operator2 since it's the only one that should be slashed. As a side effect operator3 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashedAmount = (SLASHING_FRACTION * operatorStake) / PARTS_PER_BILLION;

        vm.prank(gateway);
        middleware.slash(currentEpoch, operatorData.operatorKey, SLASHING_FRACTION);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(newEpoch);
        // Operator is paused so there should be none
        assertEq(validators.length, 0);
    }

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
    //     deal(address(operator4), OPERATOR_INITIAL_BALANCE);
    //     vm.startPrank(operator4);
    //     Token(address(stETH)).submit{value: OPERATOR_INITIAL_BALANCE}(address(operator4));

    //     //Middleware 2 Deployment
    //     vm.startPrank(network2);
    //     INetworkRegistry(networkRegistryAddress).registerNetwork();
    //     INetworkRestakeDelegator(vaultData.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);

    //     vm.startPrank(admin);
    //     INetworkRestakeDelegator(vaultData.delegator).setOperatorNetworkShares(
    //         network2.subnetwork(0), operator4, operatorShares
    //     );
    //     INetworkRestakeDelegator(vaultData.delegator).setNetworkLimit(network2.subnetwork(0), OPERATOR_NETWORK_LIMIT);
    //     _registerOperator(operator4, network2, vaultData.vault);

    //     vm.startPrank(network2);

    //     Middleware _middlewareImpl = _getMiddlewareImpl(network2, vaultFactoryAddress, networkMiddlewareServiceAddress);
    //     Middleware middleware2 = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
    //     vm.startPrank(admin);
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
    //     middleware2.registerSharedVault(vaultData.vault, stakerRewardsParams);
    //     middleware2.registerOperator(operator4, abi.encode(OPERATOR4_KEY), address(0));
    //     vm.stopPrank();

    //     vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);

    //     uint48 middlewareCurrentEpoch = middleware.getCurrentEpoch();
    //     Middleware.OperatorVaultPair[] memory operatorVaultPairs =
    //         OBaseMiddlewareReader(address(middleware)).getOperatorVaultPairs(middlewareCurrentEpoch);

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

    function _getMiddlewareImpl(
        address network,
        address vaultFactoryAddress,
        address networkMiddlewareServiceAddress
    ) private returns (Middleware middlewareImpl) {
        DeployRewards deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);

        address operatorRewards_ =
            deployRewards.deployOperatorRewardsContract(network, networkMiddlewareServiceAddress, 5000, admin);

        address stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            vaultFactoryAddress, networkMiddlewareServiceAddress, operatorRewards_, admin
        );

        middlewareImpl = new Middleware(operatorRewards_, stakerRewardsFactoryAddress);
    }

    function _prepareSlashingTest()
        public
        returns (uint48 currentEpoch, Middleware.ValidatorData[] memory validators, uint256 totalOperatorPower)
    {
        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        currentEpoch = middleware.getCurrentEpoch();

        validators = OBaseMiddlewareReader(address(middleware)).getValidatorSet(currentEpoch);
        totalOperatorPower = _calculateOperatorPower(operatorStake, 0);
    }
}
