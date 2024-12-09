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
import {Middleware} from "src/middleware/Middleware.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {NetworkMiddlewareService} from "@symbiotic/contracts/service/NetworkMiddlewareService.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {DeployCollateral} from "./DeployCollateral.s.sol";
import {DeployVault} from "./DeployVault.s.sol";
import {DeploySymbiotic} from "./DeploySymbiotic.s.sol";

import {IDefaultCollateralFactory} from
    "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateralFactory.sol";

import {Token} from "../test/mocks/Token.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {DeployCollateral} from "./DeployCollateral.s.sol";
import {DeployVault} from "./DeployVault.s.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

contract DeployTanssiEcosystem is Script {
    using Subnetwork for address;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant OPERATOR_NETWORK_SHARES = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;

    bool public isTest = false;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
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

    DeployCollateral deployCollateral;
    DeployVault deployVault;
    HelperConfig helperConfig;
    IDefaultCollateralFactory defaultCollateralFactory;
    address public defaultCollateralAddress;

    VaultConfigurator vaultConfigurator;
    OperatorRegistry operatorRegistry;
    NetworkRegistry networkRegistry;
    OptInService operatorNetworkOptInService;
    OptInService operatorVaultOptInService;
    NetworkMiddlewareService networkMiddlewareService;

    Middleware public middleware;
    Token stETHToken;
    Token rETHToken;
    Token wBTCToken;

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

    VaultAddresses public vaultAddresses;

    function deployTokens() public returns (address, address, address) {
        if (!isTest) {
            vm.stopBroadcast();
        }
        address stETH = deployCollateral.deployCollateralBroadcast("stETH");
        console2.log(" ");
        address rETH = deployCollateral.deployCollateralBroadcast("rETH");
        console2.log(" ");
        address wBTC = deployCollateral.deployCollateralBroadcast("wBTC");
        console2.log(" ");

        stETHToken = Token(stETH);
        rETHToken = Token(rETH);
        wBTCToken = Token(wBTC);

        vm.startBroadcast(ownerPrivateKey);
        stETHToken.transfer(operator, 1000 ether);
        stETHToken.transfer(operator3, 1000 ether);

        rETHToken.transfer(operator, 1000 ether);
        rETHToken.transfer(operator2, 1000 ether);
        rETHToken.transfer(operator3, 1000 ether);

        wBTCToken.transfer(operator3, 1000 ether);
        vm.stopBroadcast();

        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        }
        return (stETH, rETH, wBTC);
    }

    function deployVaults() public returns (VaultAddresses memory) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeploySymbiotic.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: !isTest,
            vaultConfigurator: address(vaultConfigurator),
            collateral: defaultCollateralAddress != address(0) ? address(defaultCollateralAddress) : address(stETHToken),
            owner: tanssi
        });

        if (!isTest) {
            vm.stopBroadcast();
        }

        console2.log("IS TEST: ", isTest);

        // On real scenario we want to deploy only the slashable vault. TBD
        if (isTest) {
            (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) =
                deployVault.createBaseVault(params);
            console2.log("Vault Collateral: ", Vault(vaultAddresses.vault).collateral());
            console2.log("Vault: ", vaultAddresses.vault);
            console2.log("Delegator: ", vaultAddresses.delegator);
            console2.log("Slasher: ", vaultAddresses.slasher);
            console2.log(" ");
        }

        if (block.chainid == 31_337) params.collateral = address(rETHToken);
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);
        console2.log("VaultSlashable Collateral: ", Vault(vaultAddresses.vaultSlashable).collateral());
        console2.log("VaultSlashable: ", vaultAddresses.vaultSlashable);
        console2.log("DelegatorSlashable: ", vaultAddresses.delegatorSlashable);
        console2.log("SlasherSlashable: ", vaultAddresses.slasherSlashable);
        console2.log(" ");

        if (isTest) {
            params.delegatorIndex = DeploySymbiotic.DelegatorIndex.FULL_RESTAKE;
            if (block.chainid == 31_337) params.collateral = address(wBTCToken);
            (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
                deployVault.createVaultVetoed(params, 1 days);
            console2.log("VaultVetoed Collateral: ", Vault(vaultAddresses.vaultVetoed).collateral());
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
        if (isTest) {
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

    function _registerOperatorToNetworkAndVault(
        address _vault
    ) public {
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(address(_vault));
    }

    function _registerEntitiesToMiddleware() public {
        if (block.chainid == 31_337 || isTest) {
            middleware.registerVault(vaultAddresses.vault);
            middleware.registerVault(vaultAddresses.vaultVetoed);
        }
        middleware.registerVault(vaultAddresses.vaultSlashable);
    }

    function _deploy() private {
        (
            address vaultConfiguratorAddress,
            address operatorRegistryAddress,
            address networkRegistryAddress,
            address vaultRegistryAddress,
            address operatorNetworkOptInServiceAddress,
            address operatorVaultOptInServiceAddress,
            address networkMiddlewareServiceAddress,
            address defaultCollateralFactoryAddress,
            address stETHAddress
        ) = helperConfig.activeNetworkConfig();

        defaultCollateralFactory = IDefaultCollateralFactory(defaultCollateralFactoryAddress);

        defaultCollateralAddress = defaultCollateralFactory.create(address(stETHAddress), 10_000 ether, address(0));
        deployVault = new DeployVault();

        networkMiddlewareService = NetworkMiddlewareService(networkMiddlewareServiceAddress);
        vaultConfigurator = VaultConfigurator(vaultConfiguratorAddress);
        operatorRegistry = OperatorRegistry(operatorRegistryAddress);
        networkRegistry = NetworkRegistry(networkRegistryAddress);
        operatorNetworkOptInService = OptInService(operatorNetworkOptInServiceAddress);
        operatorVaultOptInService = OptInService(operatorVaultOptInServiceAddress);

        networkRegistry.registerNetwork();

        if (block.chainid == 31_337) {
            // Deploy simple ERC20 collateral
            deployCollateral = new DeployCollateral();
            deployTokens();
        }

        deployVaults();

        _setDelegatorConfigs();
        middleware = new Middleware(
            tanssi,
            operatorRegistryAddress,
            vaultRegistryAddress,
            operatorNetworkOptInServiceAddress,
            tanssi,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        _registerEntitiesToMiddleware();
        networkMiddlewareService.setMiddleware(address(middleware));

        console2.log("VaultConfigurator: ", address(vaultConfigurator));
        console2.log("OperatorRegistry: ", address(operatorRegistry));
        console2.log("NetworkRegistry: ", address(networkRegistry));
        console2.log("NetworkMiddlewareService: ", address(networkMiddlewareService));
        console2.log("OperatorNetworkOptInService: ", address(operatorNetworkOptInService));
        console2.log("OperatorVaultOptInService: ", address(operatorVaultOptInService));
        console2.log("DefaultCollateralFactory: ", address(defaultCollateralFactory));
        console2.log("DefaultCollateral: ", defaultCollateralAddress);
        console2.log("Middleware: ", address(middleware));
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

    function deployTanssiEcosystem(
        HelperConfig _helperConfig
    ) external {
        helperConfig = _helperConfig;
        vm.startPrank(tanssi);
        isTest = true;
        _deploy();
        vm.stopPrank();
    }

    function run() external {
        helperConfig = new HelperConfig();

        vm.startBroadcast(ownerPrivateKey);
        isTest = false;
        _deploy();
        vm.stopBroadcast();
    }
}
