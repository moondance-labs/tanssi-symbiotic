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

import {Script, console2} from "forge-std/Script.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {MockV3Aggregator} from "@chainlink/tests/MockV3Aggregator.sol";

import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Token} from "test/mocks/Token.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract DeployTanssiEcosystemDemo is Script {
    using Subnetwork for address;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 1 minutes;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant OPERATOR_NETWORK_SHARES = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;
    uint8 public constant ORACLE_DECIMALS = 18;
    int256 public constant ORACLE_CONVERSION_TOKEN = 3000;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public tanssi = vm.addr(ownerPrivateKey);

    uint256 operatorPrivateKey =
        vm.envOr("OPERATOR_PRIVATE_KEY", uint256(0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6));
    address public operator = vm.addr(operatorPrivateKey);
    bytes32 public constant OPERATOR_KEY = bytes32(uint256(1));
    uint256 operator2PrivateKey =
        vm.envOr("OPERATOR2_PRIVATE_KEY", uint256(0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a));
    address public operator2 = vm.addr(operator2PrivateKey);
    bytes32 public constant OPERATOR_KEY2 = bytes32(uint256(2));

    uint256 operator3PrivateKey =
        vm.envOr("OPERATOR3_PRIVATE_KEY", uint256(0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba));
    address public operator3 = vm.addr(operator3PrivateKey);
    bytes32 public constant OPERATOR_KEY3 = bytes32(uint256(3));

    bytes32 public operatorKey1 = vm.envOr("OPERATOR1_KEY", OPERATOR_KEY);
    bytes32 public operatorKey2 = vm.envOr("OPERATOR2_KEY", OPERATOR_KEY2);
    bytes32 public operatorKey3 = vm.envOr("OPERATOR3_KEY", OPERATOR_KEY3);

    bool public isTest = false;
    VaultAddresses public vaultAddresses;
    TokensAddresses public tokensAddresses;
    EcosystemEntity public ecosystemEntities;
    ContractScripts public contractScripts;

    struct ContractScripts {
        DeployCollateral deployCollateral;
        DeployVault deployVault;
        HelperConfig helperConfig;
        DeployRewards deployRewards;
    }

    struct EcosystemEntity {
        Middleware middleware;
        IVaultConfigurator vaultConfigurator;
        address stETHCollateralAddress;
    }

    struct TokensAddresses {
        Token stETHToken;
        Token rETHToken;
        Token wBTCToken;
    }

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

    function deployTokens() public returns (address, address, address) {
        if (!isTest) {
            vm.stopBroadcast();
        }

        address stETH = contractScripts.deployCollateral.deployCollateralBroadcast("stETH");
        console2.log(" ");
        address rETH = contractScripts.deployCollateral.deployCollateralBroadcast("rETH");
        console2.log(" ");
        address wBTC = contractScripts.deployCollateral.deployCollateralBroadcast("wBTC");
        console2.log(" ");

        tokensAddresses.stETHToken = Token(stETH);
        tokensAddresses.rETHToken = Token(rETH);
        tokensAddresses.wBTCToken = Token(wBTC);

        vm.startBroadcast(ownerPrivateKey);
        (bool success,) = payable(operator).call{value: 100 ether}("");
        (bool success2,) = payable(operator2).call{value: 100 ether}("");
        (bool success3,) = payable(operator3).call{value: 100 ether}("");
        tokensAddresses.stETHToken.mint(tanssi, 10_000 ether);
        tokensAddresses.rETHToken.mint(tanssi, 10_000 ether);
        tokensAddresses.wBTCToken.mint(tanssi, 10_000 ether);

        tokensAddresses.stETHToken.transfer(operator, 1000 ether);
        tokensAddresses.stETHToken.transfer(operator3, 1000 ether);

        tokensAddresses.rETHToken.transfer(operator, 1000 ether);
        tokensAddresses.rETHToken.transfer(operator2, 1000 ether);
        tokensAddresses.rETHToken.transfer(operator3, 1000 ether);

        tokensAddresses.wBTCToken.transfer(operator3, 1000 ether);
        vm.stopBroadcast();

        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }
        return (stETH, rETH, wBTC);
        // return (stETH, address(0), address(0));
    }

    function deployVaults() public returns (VaultAddresses memory) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: !isTest,
            vaultConfigurator: address(ecosystemEntities.vaultConfigurator),
            collateral: ecosystemEntities.stETHCollateralAddress != address(0)
                ? ecosystemEntities.stETHCollateralAddress
                : address(tokensAddresses.stETHToken),
            owner: tanssi,
            operator: address(0),
            network: address(0),
            burner: address(0)
        });

        if (!isTest) {
            vm.stopBroadcast();
        }

        // On real scenario we want to deploy only the slashable vault. TBD
        if (isTest || block.chainid == 31_337) {
            (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) =
                contractScripts.deployVault.createBaseVault(params);
            console2.log("Vault Collateral: ", IVault(vaultAddresses.vault).collateral());
            console2.log("Vault: ", vaultAddresses.vault);
            console2.log("Delegator: ", vaultAddresses.delegator);
            console2.log("Slasher: ", vaultAddresses.slasher);
            console2.log(" ");
        }

        if (block.chainid == 31_337) {
            params.collateral = address(tokensAddresses.rETHToken);
        }
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            contractScripts.deployVault.createSlashableVault(params);
        console2.log("VaultSlashable Collateral: ", IVault(vaultAddresses.vaultSlashable).collateral());
        console2.log("VaultSlashable: ", vaultAddresses.vaultSlashable);
        console2.log("DelegatorSlashable: ", vaultAddresses.delegatorSlashable);
        console2.log("SlasherSlashable: ", vaultAddresses.slasherSlashable);
        console2.log(" ");

        if (isTest || block.chainid == 31_337) {
            params.delegatorIndex = VaultManager.DelegatorType.FULL_RESTAKE;
            if (block.chainid == 31_337) {
                params.collateral = address(tokensAddresses.wBTCToken);
            }
            (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
                contractScripts.deployVault.createVaultVetoed(params, 1 days);
            console2.log("VaultVetoed Collateral: ", IVault(vaultAddresses.vaultVetoed).collateral());
            console2.log("VaultVetoed: ", vaultAddresses.vaultVetoed);
            console2.log("DelegatorVetoed: ", vaultAddresses.delegatorVetoed);
            console2.log("SlasherVetoed: ", vaultAddresses.slasherVetoed);
            console2.log(" ");
        }

        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }
        return vaultAddresses;
    }

    function _setDelegatorConfigs() public {
        if (block.chainid == 31_337 || isTest) {
            INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);
            INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);

            INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(tanssi.subnetwork(0), MAX_NETWORK_LIMIT);
            INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(
                tanssi.subnetwork(0), MAX_NETWORK_LIMIT
            );
        }

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, MAX_NETWORK_LIMIT);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(
            tanssi.subnetwork(0), MAX_NETWORK_LIMIT
        );
    }

    function _registerEntitiesToMiddleware() public {
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });
        ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vault, stakerRewardsParams);
        ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vaultVetoed, stakerRewardsParams);
        ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vaultSlashable, stakerRewardsParams);
        ecosystemEntities.middleware.registerOperator(operator, abi.encode(operatorKey1), address(0));
        ecosystemEntities.middleware.registerOperator(operator2, abi.encode(operatorKey2), address(0));
        ecosystemEntities.middleware.registerOperator(operator3, abi.encode(operatorKey3), address(0));
    }

    function _depositToVault(IVault _vault, address _operator, uint256 _amount, Token collateral) public {
        collateral.approve(address(_vault), _amount * 10);
        _vault.deposit(_operator, _amount);
    }

    function _getEntities()
        private
        returns (
            INetworkRegistry networkRegistry,
            IOperatorRegistry operatorRegistry,
            INetworkMiddlewareService networkMiddlewareService,
            IOptInService operatorNetworkOptInService,
            IOptInService operatorVaultOptInService,
            MockV3Aggregator collateralOracle,
            address vaultRegistryAddress
        )
    {
        address vaultConfiguratorAddress;
        address operatorRegistryAddress;
        address networkRegistryAddress;
        address operatorNetworkOptInServiceAddress;
        address operatorVaultOptInServiceAddress;
        address networkMiddlewareServiceAddress;
        address stETHAddress;
        (
            vaultConfiguratorAddress,
            operatorRegistryAddress,
            networkRegistryAddress,
            vaultRegistryAddress,
            operatorNetworkOptInServiceAddress,
            operatorVaultOptInServiceAddress,
            networkMiddlewareServiceAddress,
            stETHAddress,
        ) = contractScripts.helperConfig.activeNetworkConfig();

        ecosystemEntities.vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);

        networkRegistry = INetworkRegistry(networkRegistryAddress);
        operatorRegistry = IOperatorRegistry(operatorRegistryAddress);
        networkMiddlewareService = INetworkMiddlewareService(networkMiddlewareServiceAddress);
        operatorNetworkOptInService = IOptInService(operatorNetworkOptInServiceAddress);
        operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);
        collateralOracle = new MockV3Aggregator(ORACLE_DECIMALS, ORACLE_CONVERSION_TOKEN);
    }

    function _deploy() private {
        (
            INetworkRegistry networkRegistry,
            IOperatorRegistry operatorRegistry,
            INetworkMiddlewareService networkMiddlewareService,
            IOptInService operatorNetworkOptInService,
            IOptInService operatorVaultOptInService,
            MockV3Aggregator collateralOracle,
            address vaultRegistryAddress
        ) = _getEntities();

        if (block.chainid == 31_337) {
            // Deploy simple ERC20 collateral tokens
            deployTokens();
        } else {
            networkRegistry.registerNetwork();
        }
        deployVaults();

        tokensAddresses.stETHToken.transfer{gas: 1_000_000}(operator, 1000 ether);
        tokensAddresses.stETHToken.transfer{gas: 1_000_000}(operator2, 1000 ether);
        tokensAddresses.stETHToken.transfer{gas: 1_000_000}(operator3, 1000 ether);
        tokensAddresses.rETHToken.transfer{gas: 1_000_000}(operator2, 1000 ether);
        tokensAddresses.rETHToken.transfer{gas: 1_000_000}(operator3, 1000 ether);
        vm.stopBroadcast();

        IVault _vault = IVault(vaultAddresses.vault);
        IVault _vaultSlashable = IVault(vaultAddresses.vaultSlashable);

        // Operator 1 goes to vault without slash
        // Operator 2 goes to vault 1 and 2, the latter being instant slashable
        // Operator 3 goes only to vault 2, being instant slashable
        vm.startBroadcast(operatorPrivateKey);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(vaultAddresses.vault);
        _depositToVault(_vault, operator, 100 ether, tokensAddresses.stETHToken);
        vm.stopBroadcast();

        vm.startBroadcast(operator2PrivateKey);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(vaultAddresses.vault);
        operatorVaultOptInService.optIn(vaultAddresses.vaultSlashable);
        _depositToVault(_vault, operator2, 100 ether, tokensAddresses.stETHToken);
        _depositToVault(_vaultSlashable, operator2, 100 ether, tokensAddresses.rETHToken);

        vm.stopBroadcast();

        vm.startBroadcast(operator3PrivateKey);
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(vaultAddresses.vaultSlashable);
        _depositToVault(_vaultSlashable, operator3, 100 ether, tokensAddresses.rETHToken);
        vm.stopBroadcast();

        address operatorRewardsAddress = contractScripts.deployRewards.deployOperatorRewardsContract(
            tanssi, address(networkMiddlewareService), 2000, tanssi
        );
        ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        address stakerRewardsFactoryAddress = contractScripts.deployRewards.deployStakerRewardsFactoryContract(
            vaultRegistryAddress, address(networkMiddlewareService), operatorRewardsAddress, tanssi
        );

        vm.startBroadcast(ownerPrivateKey);

        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: address(operatorRegistry),
            vaultRegistry: vaultRegistryAddress,
            operatorNetworkOptIn: address(operatorNetworkOptInService),
            owner: tanssi,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: address(0)
        });

        ecosystemEntities.middleware =
            _deployMiddlewareWithProxy(params, operatorRewardsAddress, stakerRewardsFactoryAddress);

        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(ecosystemEntities.middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(ecosystemEntities.middleware));

        // Operator 1 goes to first vault
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares{gas: 10_000_000}(
            tanssi.subnetwork(0), operator, 1
        );

        // Operator 2 goes to the first and second vault
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares{gas: 10_000_000}(
            tanssi.subnetwork(0), operator2, 1
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares{gas: 10_000_000}(
            tanssi.subnetwork(0), operator2, 1
        );

        // Operator 3 goes to the second vault
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares{gas: 10_000_000}(
            tanssi.subnetwork(0), operator3, 1
        );

        _setDelegatorConfigs();
        networkMiddlewareService.setMiddleware(address(ecosystemEntities.middleware));
        _registerEntitiesToMiddleware();

        ecosystemEntities.middleware.setCollateralToOracle(
            address(tokensAddresses.stETHToken), address(collateralOracle)
        );
        ecosystemEntities.middleware.setCollateralToOracle(
            address(tokensAddresses.rETHToken), address(collateralOracle)
        );
        ecosystemEntities.middleware.setCollateralToOracle(
            address(tokensAddresses.wBTCToken), address(collateralOracle)
        );

        console2.log("VaultConfigurator: ", address(ecosystemEntities.vaultConfigurator));
        console2.log("OperatorRegistry: ", address(operatorRegistry));
        console2.log("NetworkRegistry: ", address(networkRegistry));
        console2.log("NetworkMiddlewareService: ", address(networkMiddlewareService));
        console2.log("OperatorNetworkOptInService: ", address(operatorNetworkOptInService));
        console2.log("OperatorVaultOptInService: ", address(operatorVaultOptInService));
        console2.log("stETHCollateralAddress: ", ecosystemEntities.stETHCollateralAddress);
        console2.log("Middleware: ", address(ecosystemEntities.middleware));
        console2.log("Vault: ", vaultAddresses.vault);
        console2.log("Delegator: ", vaultAddresses.delegator);
        console2.log("Slasher: ", vaultAddresses.slasher);
        console2.log("Vault Slashable: ", vaultAddresses.vaultSlashable);
        console2.log("Delegator Slashable: ", vaultAddresses.delegatorSlashable);
        console2.log("Slasher Slashable: ", vaultAddresses.slasherSlashable);
        console2.log("Vault Vetoed: ", vaultAddresses.vaultVetoed);
        console2.log("Delegator Vetoed: ", vaultAddresses.delegatorVetoed);
        console2.log("Slasher Vetoed: ", vaultAddresses.slasherVetoed);
    }

    function _deployMiddlewareWithProxy(
        IMiddleware.InitParams memory params,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress
    ) private returns (Middleware _middleware) {
        Middleware _middlewareImpl = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));
        console2.log("Middleware Implementation: ", address(_middlewareImpl));

        if (params.reader == address(0)) {
            params.reader = address(new OBaseMiddlewareReader());
        }
        _middleware.initialize(params);
    }

    function deployTanssiEcosystem(
        HelperConfig _helperConfig
    ) external {
        isTest = true;
        contractScripts.helperConfig = _helperConfig;
        contractScripts.deployVault = new DeployVault();
        contractScripts.deployCollateral = new DeployCollateral();
        contractScripts.deployRewards = new DeployRewards();
        contractScripts.deployRewards.setIsTest(isTest);

        vm.startPrank(tanssi);
        _deploy();
        vm.stopPrank();
    }

    function run() external {
        isTest = false;
        contractScripts.helperConfig = new HelperConfig();
        contractScripts.deployVault = new DeployVault();
        contractScripts.deployCollateral = new DeployCollateral();
        contractScripts.deployRewards = new DeployRewards();
        contractScripts.deployRewards.setIsTest(isTest);
        vm.startBroadcast(ownerPrivateKey);
        _deploy();
        vm.stopBroadcast();
    }
}
