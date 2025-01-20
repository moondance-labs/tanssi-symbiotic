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
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {MetadataService} from "@symbiotic/contracts/service/MetadataService.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {VaultTokenized} from "@symbiotic/contracts/vault/VaultTokenized.sol";
import {NetworkRestakeDelegator} from "@symbiotic/contracts/delegator/NetworkRestakeDelegator.sol";
import {FullRestakeDelegator} from "@symbiotic/contracts/delegator/FullRestakeDelegator.sol";
import {OperatorSpecificDelegator} from "@symbiotic/contracts/delegator/OperatorSpecificDelegator.sol";
import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {CreateAgentParams, CreateChannelParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {OperatingMode, ParaID} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Types.sol";
import {MockGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockGateway.sol";
import {GatewayProxy} from "@tanssi-bridge-relayer/snowbridge/contracts/src/GatewayProxy.sol";
import {AgentExecutor} from "@tanssi-bridge-relayer/snowbridge/contracts/src/AgentExecutor.sol";
import {SetOperatingModeParams} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Params.sol";
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {Gateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/Gateway.sol";
import {MockOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/test/mocks/MockOGateway.sol";

import {UD60x18, ud60x18} from "prb/math/src/UD60x18.sol";

import {Middleware} from "src/middleware/Middleware.sol";
import {Token} from "test/mocks/Token.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    uint48 public constant VAULT_EPOCH_DURATION = 8 days;
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
    uint256 public constant OPERATOR_SHARE = 1;
    uint256 public constant TOTAL_NETWORK_SHARES = 3;

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
    Token public stETH;
    Token public rETH;
    Token public wBTC;
    VaultConfigurator public vaultConfigurator;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    address public owner = vm.addr(ownerPrivateKey);

    address public operator = makeAddr("operator");

    address public operator2 = makeAddr("operator2");

    address public operator3 = makeAddr("operator3");

    address public resolver1 = makeAddr("resolver1");
    address public resolver2 = makeAddr("resolver2");

    address tanssi;
    address otherNetwork;

    VaultAddresses public vaultAddresses;
    Vault vault;
    Vault vaultSlashable;
    Vault vaultVetoed;
    Vault[] public vaults;

    VetoSlasher vetoSlasher;

    // Scripts
    DeployVault deployVault;

    function setUp() public {
        DeployCollateral deployCollateral = new DeployCollateral();

        vm.startPrank(owner);
        address stETHAddress = deployCollateral.deployCollateral("stETH");
        stETH = Token(stETHAddress);
        stETH.mint(owner, 1_000_000 ether);
        address rETHAddress = deployCollateral.deployCollateral("rETH");
        rETH = Token(rETHAddress);
        rETH.mint(owner, 1_000_000 ether);
        address wBTCAddress = deployCollateral.deployCollateral("wBTC");
        wBTC = Token(wBTCAddress);
        wBTC.mint(owner, 1_000_000 ether);
        vm.stopPrank();

        deployVault = new DeployVault();
        DeploySymbiotic deploySymbiotic = new DeploySymbiotic();

        owner = tanssi = deploySymbiotic.owner();

        DeploySymbiotic.SymbioticAddresses memory symbioticAddresses = deploySymbiotic.deploySymbiotic(owner);
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

        vm.startPrank(tanssi);
        // Send initial collateral to the operators
        stETH.transfer(operator, OPERATOR_INITIAL_BALANCE);

        rETH.transfer(operator2, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator2, OPERATOR_INITIAL_BALANCE);

        stETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        rETH.transfer(operator3, OPERATOR_INITIAL_BALANCE);
        wBTC.transfer(operator3, OPERATOR_INITIAL_BALANCE);

        _deployVaults(tanssi);

        middleware = new Middleware(
            tanssi,
            address(operatorRegistry),
            address(vaultFactory),
            address(operatorNetworkOptInService),
            owner,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        networkMiddlewareService.setMiddleware(address(middleware));

        vetoSlasher = VetoSlasher(vaultAddresses.slasherVetoed);

        vetoSlasher.setResolver(0, resolver1, hex"");
        vetoSlasher.setResolver(0, resolver2, hex"");
        vm.stopPrank();

        vault = Vault(vaultAddresses.vault);
        vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        vaultVetoed = Vault(vaultAddresses.vaultVetoed);
        vaults.push(vault);
        vaults.push(vaultSlashable);
        vaults.push(vaultVetoed);

        _registerOperator(operator, tanssi, address(vault));
        _registerOperator(operator3, tanssi, address(vaultSlashable));
        _registerOperator(operator2, tanssi, address(vaultVetoed));

        _registerEntitiesToMiddleware(owner);
        _setOperatorsNetworkShares(tanssi);

        _setLimitForNetworkAndOperators(tanssi);

        vm.startPrank(operator);
        _depositToVault(vault, operator, 100 ether, stETH);

        vm.startPrank(operator2);
        operatorVaultOptInService.optIn(address(vaultSlashable));
        _depositToVault(vaultSlashable, operator2, 100 ether, rETH);
        _depositToVault(vaultVetoed, operator2, 100 ether, wBTC);
        vm.stopPrank();

        vm.startPrank(operator3);
        operatorVaultOptInService.optIn(address(vault));
        operatorVaultOptInService.optIn(address(vaultVetoed));
        _depositToVault(vault, operator3, 100 ether, stETH);
        _depositToVault(vaultSlashable, operator3, 100 ether, rETH);
        _depositToVault(vaultVetoed, operator3, 100 ether, wBTC);

        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        HELPERS
    // ************************************************************************************************

    function _deployVaults(
        address _owner
    ) public {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeploySymbiotic.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(stETH),
            owner: _owner
        });

        (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) = deployVault.createBaseVault(params);

        params.collateral = address(rETH);
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);

        params.collateral = address(wBTC);
        params.delegatorIndex = DeploySymbiotic.DelegatorIndex.FULL_RESTAKE;
        (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
            deployVault.createVaultVetoed(params, 1 days);
    }

    function _depositToVault(Vault _vault, address _operator, uint256 _amount, Token collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _registerEntitiesToMiddleware(
        address _owner
    ) public {
        vm.startPrank(_owner);
        middleware.registerVault(vaultAddresses.vault);
        middleware.registerVault(vaultAddresses.vaultSlashable);
        middleware.registerVault(vaultAddresses.vaultVetoed);
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
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);

        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, 300 ether
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
        vm.warp(NETWORK_EPOCH_DURATION + 1);
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

        vm.warp(NETWORK_EPOCH_DURATION + 1);
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

        vm.warp(VAULT_EPOCH_DURATION * 2 + 1);
        currentEpoch = vaultSlashable.currentEpoch();
        vm.prank(operator2);
        vaultSlashable.claim(operator2, currentEpoch - 1);
        assertEq(rETH.balanceOf(operator2), OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE + DEFAULT_WITHDRAW_AMOUNT);
    }

    function testSlashingOnOperator2AndVetoingSlash() public {
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
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

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator2Stake);
        middleware.slash(currentEpoch, operator2, slashingFraction);

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

    function testSlashingOnOperator2ButWrongSlashingWindow() public {
        vm.warp(NETWORK_EPOCH_DURATION * 2 + SLASHING_WINDOW / 2);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        uint256 epochStartTs = middleware.getEpochStartTs(currentEpoch);

        // We go directly to epochStart as it 100% ensure that the epoch is started and thus the slashing is invalid
        vm.warp(epochStartTs);

        //InvalidCaptureTimestamp
        bytes memory data = "\x26\xaf\x59\x22";

        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);
        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator2Stake);

        uint256 slashedEvent = activeStakeInVetoed * slashingFraction / 1_000_000_000;

        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit Middleware.SlashFailure(data, tanssi.subnetwork(0), operator2, slashedEvent, uint48(epochStartTs));
        middleware.slash(currentEpoch, operator2, slashingFraction);
    }

    function testSlashingOnOperator2AndExecuteSlashOnVetoVault() public {
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
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

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator2Stake);
        middleware.slash(currentEpoch, operator2, slashingFraction);

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
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
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

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator3Stake);
        middleware.slash(currentEpoch, operator3, slashingFraction);

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
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();

        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);
        //Since vaultVetoed is full restake, it exactly gets the amount deposited, so no need to calculations
        uint256 activeStakeInVetoed = vaultVetoed.activeStake();

        (uint256 totalOperator2Stake, uint256 remainingOperator2Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        (uint256 totalOperator3Stake, uint256 remainingOperator3Stake) =
            _calculateTotalOperatorStake(OPERATOR_STAKE * 2, activeStakeInVetoed, 0);

        assertEq(validators[1].stake, totalOperator2Stake);
        //We need to assert like this instead of putting OPERATOR_STAKE * 2 * 2 because of the precision loss. We know that remainingOperator3Stake will be the same even for the other (non slashable) vault so we can just sum it.
        assertEq(validators[2].stake, totalOperator3Stake + remainingOperator3Stake);

        //We calculate the amount slashable for only the operator3 since it's the only one that should be slashed. As a side effect operator2 will be slashed too since it's taking part in a NetworkRestake delegator based vault
        uint256 slashAmountSlashable3 =
            (SLASH_AMOUNT * remainingOperator3Stake) / (totalOperator3Stake + remainingOperator3Stake);

        vm.prank(owner);

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage

        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator3Stake + remainingOperator3Stake);
        middleware.slash(currentEpoch, operator3, slashingFraction);

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
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
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

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator2Stake);

        vm.prank(owner);
        middleware.pauseVault(vaultAddresses.vaultSlashable);

        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, slashingFraction);
        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        uint48 newEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(newEpoch);

        assertEq(validators[1].stake, OPERATOR_STAKE * 2);
        assertEq(validators[2].stake, OPERATOR_STAKE * 2 + remainingOperator2Stake);
    }

    function testSlashingAndPausingOperator() public {
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
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

        uint256 slashedAmount = 30 ether;
        // We want to slash 30 ether, so we need to calculate what percentage
        uint256 slashingFraction = slashedAmount.mulDiv(1_000_000_000, totalOperator2Stake);
        //! Why this slash should anyway go through if operator was paused? Shouldn't it revert?
        middleware.slash(currentEpoch, operator2, slashingFraction);
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

        //Middleware 2 Deployment
        vm.startPrank(network2);
        networkRegistry.registerNetwork();
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);

        vm.startPrank(owner);
        stETH.transfer(operator4, OPERATOR_INITIAL_BALANCE);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(
            network2.subnetwork(0), operator4, OPERATOR_SHARE
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(network2.subnetwork(0), 300 ether);

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
        vm.warp(NETWORK_EPOCH_DURATION + 1);
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

    function _createGateway() internal returns (address) {
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
        GatewayProxy gateway = new GatewayProxy(address(gatewayLogic), abi.encode(config));
        MockGateway(address(gateway)).setCommitmentsAreVerified(true);

        SetOperatingModeParams memory operatingModeParams = SetOperatingModeParams({mode: OperatingMode.Normal});
        MockGateway(address(gateway)).setOperatingModePublic(abi.encode(operatingModeParams));

        return address(gateway);
    }

    function _createParaIDAndAgent(
        IOGateway gateway
    ) public returns (ParaID) {
        ParaID paraID = ParaID.wrap(1);
        bytes32 agentID = keccak256("1");

        MockGateway(address(gateway)).createAgentPublic(abi.encode(CreateAgentParams({agentID: agentID})));

        CreateChannelParams memory params =
            CreateChannelParams({channelID: paraID.into(), agentID: agentID, mode: OperatingMode.Normal});

        MockGateway(address(gateway)).createChannelPublic(abi.encode(params));
        return paraID;
    }

    function testSendingOperatorsDataToGateway() public {
        IOGateway gateway = IOGateway(address(_createGateway()));
        _createParaIDAndAgent(gateway);
        vm.startPrank(owner);
        middleware.setGateway(address(gateway));
        middleware.sendCurrentOperatorsKeys();
        vm.stopPrank();
    }
}
