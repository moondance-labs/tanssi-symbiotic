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
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IDefaultCollateralFactory} from
    "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateralFactory.sol";
import {DefaultCollateralFactory} from "@symbiotic-collateral/contracts/defaultCollateral/DefaultCollateralFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";

import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Token} from "test/mocks/Token.sol";
import {DeployCollateral} from "./DeployCollateral.s.sol";
import {DeployVault} from "./DeployVault.s.sol";
import {DeployRewards} from "./DeployRewards.s.sol";
import {DeploySymbiotic} from "./DeploySymbiotic.s.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract DeployTanssiEcosystem is Script {
    using Subnetwork for address;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant OPERATOR_NETWORK_SHARES = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;

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

    bool public isTest = false;
    VaultAddresses public vaultAddresses; // For testing only
    EcosystemEntity public ecosystemEntities;
    CollateralAddresses public collateralAddresses;
    TestCollateralAddresses public testCollateralAddresses;
    ContractScripts public contractScripts;

    struct ContractScripts {
        DeployCollateral deployCollateral;
        DeployVault deployVault;
        DeployRewards deployRewards;
        HelperConfig helperConfig;
    }

    struct EcosystemEntity {
        Middleware middleware;
        IVaultConfigurator vaultConfigurator;
    }

    struct CollateralAddresses {
        address stETH;
        address rETH;
        address swETH;
        address wBETH;
        address LsETH;
        address cbETH;
    }

    struct TestCollateralAddresses {
        Token stETH;
        Token rETH;
        Token wBTC;
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

    function deployTokens(
        address owner
    ) public returns (address, address, address) {
        address stETH = contractScripts.deployCollateral.deployCollateral("stETH");
        console2.log(" ");
        address rETH = contractScripts.deployCollateral.deployCollateral("rETH");
        console2.log(" ");
        address wBTC = contractScripts.deployCollateral.deployCollateral("wBTC");
        console2.log(" ");

        testCollateralAddresses.stETH = Token(stETH);
        testCollateralAddresses.rETH = Token(rETH);
        testCollateralAddresses.wBTC = Token(wBTC);

        testCollateralAddresses.stETH.mint{gas: 1_000_000}(owner, 10_000 ether);
        testCollateralAddresses.rETH.mint(owner, 10_000 ether);
        testCollateralAddresses.wBTC.mint(owner, 10_000 ether);

        return (stETH, rETH, wBTC);
    }

    function deployVaults() public returns (VaultAddresses memory) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: !isTest,
            vaultConfigurator: address(ecosystemEntities.vaultConfigurator),
            collateral: collateralAddresses.stETH != address(0)
                ? collateralAddresses.stETH
                : address(testCollateralAddresses.stETH),
            owner: tanssi,
            operator: address(0),
            network: address(0)
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
            params.collateral = address(testCollateralAddresses.rETH);
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
                params.collateral = address(testCollateralAddresses.wBTC);
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

    function _setDelegatorConfigs() private {
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

    function _registerEntitiesToMiddleware() private {
        IODefaultStakerRewards.InitParams memory stakerRewardsParams = IODefaultStakerRewards.InitParams({
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi
        });
        if (block.chainid != 1) {
            if (block.chainid == 31_337 || isTest) {
                ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vault, stakerRewardsParams);
                ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vaultVetoed, stakerRewardsParams);
            }
            ecosystemEntities.middleware.registerSharedVault(vaultAddresses.vaultSlashable, stakerRewardsParams);
        }
    }

    function _transferTokensToOperators() private {
        // vm.startBroadcast(ownerPrivateKey);
        testCollateralAddresses.stETH.transfer{gas: 1_000_000}(operator, 1000 ether);
        testCollateralAddresses.stETH.transfer{gas: 1_000_000}(operator3, 1000 ether);

        testCollateralAddresses.rETH.transfer(operator, 1000 ether);
        testCollateralAddresses.rETH.transfer(operator2, 1000 ether);
        testCollateralAddresses.rETH.transfer(operator3, 1000 ether);

        testCollateralAddresses.wBTC.transfer(operator3, 1000 ether);
    }

    function _deployCollateralFactory() private {
        (,,,,,,, address defaultCollateralFactoryAddress,) = contractScripts.helperConfig.activeNetworkConfig();

        (
            address stETHAddress,
            address rETHAddress,
            address swETHAddress,
            address wBETHAddress,
            address LsETHAddress,
            address cbETHAddress
        ) = contractScripts.helperConfig.activeTokensConfig();

        if (block.chainid != 31_337 && block.chainid != 1) {
            if (defaultCollateralFactoryAddress == address(0)) {
                defaultCollateralFactoryAddress = address(new DefaultCollateralFactory());
            }

            collateralAddresses.stETH = IDefaultCollateralFactory(defaultCollateralFactoryAddress).create(
                address(stETHAddress), 10_000 ether, address(0)
            );
        }

        if (!isTest) {
            console2.log("DefaultCollateralFactory: ", defaultCollateralFactoryAddress);
            console2.log("StETH: ", stETHAddress);
        }
    }

    function _deploy() private {
        (
            ,
            address operatorRegistryAddress,
            address networkRegistryAddress,
            address vaultRegistryAddress,
            address operatorNetworkOptInServiceAddress,
            address operatorVaultOptInServiceAddress,
            address networkMiddlewareServiceAddress,
            ,
        ) = contractScripts.helperConfig.activeNetworkConfig();

        _deployCollateralFactory();

        INetworkMiddlewareService networkMiddlewareService = INetworkMiddlewareService(networkMiddlewareServiceAddress);

        if (block.chainid == 31_337) {
            // Deploy simple ERC20 collateral tokens
            deployTokens(tanssi);
            _transferTokensToOperators();
        } else {
            if (!INetworkRegistry(networkRegistryAddress).isEntity(tanssi)) {
                INetworkRegistry(networkRegistryAddress).registerNetwork();
            }
        }
        if (block.chainid != 1) {
            deployVaults();
            _setDelegatorConfigs();
        }

        if (!isTest) {
            vm.stopBroadcast();
        }

        address operatorRewardsAddress = contractScripts.deployRewards.deployOperatorRewardsContract(
            tanssi, networkMiddlewareServiceAddress, 2000, tanssi
        );
        ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);

        address stakerRewardsFactoryAddress = contractScripts.deployRewards.deployStakerRewardsFactoryContract(
            vaultRegistryAddress, networkMiddlewareServiceAddress, operatorRewardsAddress, tanssi
        );

        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }

        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: operatorRegistryAddress,
            vaultRegistry: vaultRegistryAddress,
            operatorNetworkOptIn: operatorNetworkOptInServiceAddress,
            owner: tanssi,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: address(0)
        });

        ecosystemEntities.middleware =
            deployMiddlewareWithProxy(params, operatorRewardsAddress, stakerRewardsFactoryAddress);

        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(ecosystemEntities.middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(ecosystemEntities.middleware));

        networkMiddlewareService.setMiddleware(address(ecosystemEntities.middleware));
        _registerEntitiesToMiddleware();

        if (!isTest) {
            console2.log("VaultConfigurator: ", address(ecosystemEntities.vaultConfigurator));
            console2.log("OperatorRegistry: ", operatorRegistryAddress);
            console2.log("NetworkRegistry: ", networkRegistryAddress);
            console2.log("NetworkMiddlewareService: ", networkMiddlewareServiceAddress);
            console2.log("OperatorNetworkOptInService: ", operatorNetworkOptInServiceAddress);
            console2.log("OperatorVaultOptInService: ", operatorVaultOptInServiceAddress);
            console2.log("stETHCollateralAddress: ", collateralAddresses.stETH);
            console2.log("Middleware: ", address(ecosystemEntities.middleware));
            console2.log("OperatorRewards: ", operatorRewardsAddress);
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
    }

    function deployMiddlewareWithProxy(
        IMiddleware.InitParams memory params,
        address operatorRewards,
        address stakerRewardsFactory
    ) public returns (Middleware _middleware) {
        Middleware _middlewareImpl = new Middleware(operatorRewards, stakerRewardsFactory);
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));

        if (params.reader == address(0)) {
            params.reader = address(new OBaseMiddlewareReader());
        }
        _middleware.initialize(params);
    }

    function deployMiddleware(
        IMiddleware.InitParams memory params,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress,
        address networkMiddlewareServiceAddress
    ) external returns (address) {
        vm.startBroadcast(ownerPrivateKey);

        ecosystemEntities.middleware =
            deployMiddlewareWithProxy(params, operatorRewardsAddress, stakerRewardsFactoryAddress);

        if (networkMiddlewareServiceAddress != address(0)) {
            INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(
                address(ecosystemEntities.middleware)
            );
        }

        vm.stopBroadcast();
        return address(ecosystemEntities.middleware);
    }

    function registerSharedVault(
        address middlewareAddress,
        address vaultAddress,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) external {
        Middleware middleware = Middleware(middlewareAddress);
        vm.startBroadcast(ownerPrivateKey);
        middleware.registerSharedVault(vaultAddress, stakerRewardsParams);
        vm.stopBroadcast();
    }

    function registerMiddlewareToSymbiotic(
        address networkMiddlewareServiceAddress
    ) external {
        INetworkMiddlewareService networkMiddlewareService = INetworkMiddlewareService(networkMiddlewareServiceAddress);
        vm.startBroadcast(ownerPrivateKey);
        networkMiddlewareService.setMiddleware(address(ecosystemEntities.middleware));
        vm.stopBroadcast();
    }

    function deployTanssiEcosystem(
        HelperConfig _helperConfig
    ) external {
        isTest = true;
        _initScriptsAndEntities(_helperConfig);

        vm.startPrank(tanssi);
        _deploy();
        vm.stopPrank();
    }

    function run() external {
        isTest = false;
        _initScriptsAndEntities(new HelperConfig());

        vm.startBroadcast(ownerPrivateKey);
        _deploy();
        vm.stopBroadcast();
    }

    function upgradeMiddlewareBroadcast(
        address proxyAddress,
        uint256 expectedCurrentVersion,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress
    ) external {
        isTest = false;
        upgradeMiddleware(
            proxyAddress, expectedCurrentVersion, operatorRewardsAddress, stakerRewardsFactoryAddress, address(0)
        );
    }

    function upgradeMiddleware(
        address proxyAddress,
        uint256 expectedCurrentVersion,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress,
        address contractOwner
    ) public {
        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        } else {
            vm.startPrank(contractOwner);
        }
        Middleware newImplementation = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
        Middleware proxy = Middleware(proxyAddress);
        uint256 currentVersion = proxy.VERSION();
        if (currentVersion != expectedCurrentVersion) {
            revert("Middleware version is not expected, cannot upgrade");
        }
        proxy.upgradeToAndCall(address(newImplementation), hex"");
        console2.log("New implementation: ", address(newImplementation));
        if (!isTest) {
            vm.stopBroadcast();
        } else {
            vm.stopPrank();
        }
    }

    function getStETHCollateralAddress() external view returns (address) {
        return collateralAddresses.stETH;
    }

    function _initScriptsAndEntities(
        HelperConfig _helperConfig
    ) private {
        contractScripts.helperConfig = _helperConfig;
        contractScripts.deployVault = new DeployVault();
        contractScripts.deployCollateral = new DeployCollateral();
        contractScripts.deployRewards = new DeployRewards();
        contractScripts.deployRewards.setIsTest(isTest);

        (address vaultConfiguratorAddress,,,,,,,,) = _helperConfig.activeNetworkConfig();
        ecosystemEntities.vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);
    }
}
