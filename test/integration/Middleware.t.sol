// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";

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
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Token} from "../mocks/Token.sol";
import {Middleware} from "../../src/middleware/Middleware.sol";

import {DeploySymbiotic} from "../../script/DeploySymbiotic.s.sol";
import {DeployCollateral} from "../../script/DeployCollateral.s.sol";
import {DeployVault} from "../../script/DeployVault.s.sol";

contract MiddlewareTest is Test {
    using Subnetwork for address;
    using Subnetwork for bytes32;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint256 public constant OPERATOR_STAKE = 100 ether;
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;
    uint256 public constant MIN_SLASHING_WINDOW = 1 days;
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    bytes32 public constant OPERATOR2_KEY = bytes32(uint256(2));
    bytes32 public constant OPERATOR3_KEY = bytes32(uint256(3));

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
    Token public collateral;
    VaultConfigurator public vaultConfigurator;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    address public owner = vm.addr(ownerPrivateKey);

    uint256 operatorPrivateKey =
        vm.envOr("OPERATOR_PRIVATE_KEY", uint256(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a));
    address public operator = vm.addr(operatorPrivateKey);

    uint256 operator2PrivateKey =
        vm.envOr("OPERATOR2_PRIVATE_KEY", uint256(0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a));
    address public operator2 = vm.addr(operator2PrivateKey);

    uint256 operator3PrivateKey =
        vm.envOr("OPERATOR3_PRIVATE_KEY", uint256(0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba));
    address public operator3 = vm.addr(operator3PrivateKey);

    address network;

    VaultAddresses public vaultAddresses;
    Vault vault;
    Vault vaultSlashable;
    Vault vaultVetoed;

    function setUp() public {
        DeployCollateral deployCollateral = new DeployCollateral();

        vm.startPrank(owner);
        address collateralAddress = deployCollateral.deployCollateral("Test");
        collateral = Token(collateralAddress);
        collateral.mint(owner, 1_000_000 ether);
        vm.stopPrank();

        DeployVault deployVault = new DeployVault();
        DeploySymbiotic deploySymbiotic = new DeploySymbiotic();
        deploySymbiotic.setCollateral(address(collateral));

        owner = network = deploySymbiotic.owner();
        console2.log("Owner: ", owner);
        console2.log("Network: ", network);

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

        vm.startPrank(network);
        // Send initial collateral to the operators
        collateral.transfer(operator, OPERATOR_INITIAL_BALANCE);
        collateral.transfer(operator2, OPERATOR_INITIAL_BALANCE);
        collateral.transfer(operator3, OPERATOR_INITIAL_BALANCE);

        _deployVaults(deployVault);

        middleware = new Middleware(
            network,
            address(operatorRegistry),
            address(vaultFactory),
            address(operatorNetworkOptInService),
            owner,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        networkMiddlewareService.setMiddleware(address(middleware));
        console2.log("Middleware for network: ", networkMiddlewareService.middleware(network));
        vm.stopPrank();

        _registerOperator(operator, vaultAddresses.vault);
        _registerOperator(operator3, vaultAddresses.vaultSlashable);
        _registerOperator(operator2, vaultAddresses.vaultVetoed);

        _registerEntitiesToMiddleware();
        _setOperatorsNetworkShares();

        _setLimitForNetworkAndOperators();

        vault = Vault(vaultAddresses.vault);
        vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        vaultVetoed = Vault(vaultAddresses.vaultVetoed);

        vm.startPrank(operator);
        collateral.approve(vaultAddresses.vault, 1000 ether);
        vault.deposit(operator, 100 ether);

        vm.startPrank(operator2);
        operatorVaultOptInService.optIn(address(vaultSlashable));
        collateral.approve(address(vaultSlashable), 1000 ether);
        collateral.approve(address(vaultVetoed), 1000 ether);
        vaultVetoed.deposit(operator2, 100 ether);
        vaultSlashable.deposit(operator2, 100 ether);
        vm.stopPrank();

        vm.startPrank(operator3);
        operatorVaultOptInService.optIn(address(vault));
        operatorVaultOptInService.optIn(address(vaultVetoed));
        collateral.approve(address(vault), 1000 ether);
        collateral.approve(address(vaultSlashable), 1000 ether);
        collateral.approve(address(vaultVetoed), 1000 ether);
        vault.deposit(operator3, 100 ether);
        vaultSlashable.deposit(operator3, 100 ether);
        vaultVetoed.deposit(operator3, 100 ether);
        vm.stopPrank();
    }

    // ************************************************************************************************
    // *                                        HELPERS
    // ************************************************************************************************

    function _deployVaults(
        DeployVault deployVault
    ) public {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeploySymbiotic.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(collateral)
        });

        (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) = deployVault.createBaseVault(params);

        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);

        params.delegatorIndex = DeploySymbiotic.DelegatorIndex.FULL_RESTAKE;
        (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
            deployVault.createVaultVetoed(params, 1 days);
    }

    function _registerEntitiesToMiddleware() public {
        vm.startPrank(owner);
        middleware.registerVault(vaultAddresses.vault);
        middleware.registerVault(vaultAddresses.vaultSlashable);
        middleware.registerVault(vaultAddresses.vaultVetoed);
        middleware.registerOperator(operator, OPERATOR_KEY);
        middleware.registerOperator(operator2, OPERATOR2_KEY);
        middleware.registerOperator(operator3, OPERATOR3_KEY);
        vm.stopPrank();
    }

    function _registerOperator(address _operator, address _vault) public {
        vm.startPrank(_operator);
        operatorRegistry.registerOperator();
        operatorVaultOptInService.optIn(address(_vault));
        operatorNetworkOptInService.optIn(network);
        vm.stopPrank();
    }

    function _setOperatorsNetworkShares() public {
        vm.startPrank(owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(network.subnetwork(0), operator, 1);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(network.subnetwork(0), operator2, 1);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(network.subnetwork(0), operator3, 1);

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            network.subnetwork(0), operator, 1
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            network.subnetwork(0), operator2, 1
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            network.subnetwork(0), operator3, 1
        );
        vm.stopPrank();
    }

    function _setLimitForNetworkAndOperators() public {
        vm.startPrank(owner);
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(network.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(network.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(network.subnetwork(0), 1000 ether);

        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            network.subnetwork(0), operator, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            network.subnetwork(0), operator2, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            network.subnetwork(0), operator3, 300 ether
        );
        vm.stopPrank();
    }
    // ************************************************************************************************
    // *                                        BASE TESTS
    // ************************************************************************************************

    function testInitialState() public view {
        assertEq(middleware.i_network(), network);
        assertEq(middleware.i_operatorRegistry(), address(operatorRegistry));
        assertEq(middleware.i_vaultRegistry(), address(vaultFactory));
        assertEq(middleware.i_epochDuration(), NETWORK_EPOCH_DURATION);
        assertEq(middleware.i_slashingWindow(), SLASHING_WINDOW);
        assertEq(middleware.s_subnetworksCount(), 1);
    }

    function testIfOperatorsAreRegisteredInVaults() public view {
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPair(currentEpoch);
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
        assertEq(validators.length, 2);

        Middleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPair(currentEpoch);
        assertEq(operatorVaultPairs.length, 2);
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

    //Test slashing
    function testWithdraw() public {
        vm.prank(operator2);
        console2.log("Active balance: ", vaultSlashable.activeBalanceOf(operator2));
        console2.log("Withdrawals: ", vaultSlashable.withdrawalsOf(0, operator2));
        vm.prank(operator2);
        vaultSlashable.withdraw(operator2, 100 ether);
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW + 1);
        vm.prank(operator2);

        console2.log("Active balance: ", vaultSlashable.activeBalanceOf(operator2));
        console2.log("Withdrawals: ", vaultSlashable.withdrawalsOf(0, operator2));
        vaultSlashable.claim(operator2, 0);
        assertEq(collateral.balanceOf(operator2), OPERATOR_INITIAL_BALANCE - OPERATOR_STAKE);
    }

    function testSlashing() public {
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW - 1);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        Middleware.ValidatorData[] memory validators = middleware.getValidatorSet(currentEpoch);

        console2.log("Validator stake: ", validators[1].stake);
        vm.prank(owner);
        middleware.slash(currentEpoch, operator2, 30 ether);
        console2.log("Active Shares: ", vaultSlashable.activeShares());
        console2.log("Active Stake: ", vaultSlashable.activeStake());
        console2.log("Active Stake: ", vaultVetoed.activeStake());
        console2.log("Active Shares Of: ", vaultSlashable.activeSharesOf(operator2));
        console2.log(
            "totalOperatorNetworkSharesAt: ",
            INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).totalOperatorNetworkSharesAt(
                network.subnetwork(0), uint48(block.timestamp), "0x"
            )
        );
        vm.warp(NETWORK_EPOCH_DURATION + SLASHING_WINDOW);
        currentEpoch = middleware.getCurrentEpoch();
        validators = middleware.getValidatorSet(currentEpoch);
        assertEq(validators[1].stake, OPERATOR_STAKE);
    }
    // 66666666666666666666
    // 266666666666666666666
    // 333333333333333333332
}
// 266666666666666666666
// 66666666666666666666
// 30000000000000000000

// 30000000000000000000
// 200000000000000000000
// 266666666666666666666
