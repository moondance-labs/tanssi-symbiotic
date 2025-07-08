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
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

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
import {OperatorNetworkSpecificDelegator} from "@symbiotic/contracts/delegator/OperatorNetworkSpecificDelegator.sol";

import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

//**************************************************************************************************
//                                      DEVOPS
//**************************************************************************************************
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";

//**************************************************************************************************
//                                      MOCKS
//**************************************************************************************************
import {Token} from "../test/mocks/Token.sol";

import {DeployVault} from "./DeployVault.s.sol";

contract DeploySymbiotic is Script {
    error DeploySymbiotic__VaultConfiguratorOrCollateralNotDeployed();
    error DeploySymbiotic__VaultsAddresseslNotDeployed();

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant VETO_DURATION = 1 days;

    // These can be hardcoded since they are anvil private keys
    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public owner = vm.addr(ownerPrivateKey);

    uint256 operatorPrivateKey =
        vm.envOr("OPERATOR_PRIVATE_KEY", uint256(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a));
    address public operator = vm.addr(operatorPrivateKey);
    bool public isTest = false;

    VaultConfigurator vaultConfigurator;
    Token public collateral;
    DeployVault deployVault;

    struct SymbioticAddresses {
        address vaultFactory;
        address delegatorFactory;
        address slasherFactory;
        address networkRegistry;
        address operatorRegistry;
        address operatorMetadataService;
        address networkMetadataService;
        address networkMiddlewareService;
        address operatorVaultOptInService;
        address operatorNetworkOptInService;
        address vaultImpl;
        address vaultTokenizedImpl;
        address networkRestakeDelegatorImpl;
        address fullRestakeDelegatorImpl;
        address operatorSpecificDelegatorImpl;
        address slasherImpl;
        address vetoSlasherImpl;
        address vaultConfigurator;
    }

    struct DeployedFactories {
        VaultFactory vaultFactory;
        DelegatorFactory delegatorFactory;
        SlasherFactory slasherFactory;
    }

    struct DeployedRegistries {
        NetworkRegistry networkRegistry;
        OperatorRegistry operatorRegistry;
    }

    struct DeployedServices {
        MetadataService operatorMetadataService;
        MetadataService networkMetadataService;
        NetworkMiddlewareService networkMiddlewareService;
        OptInService operatorVaultOptInService;
        OptInService operatorNetworkOptInService;
    }

    function setCollateral(
        address collateralAddress
    ) public {
        collateral = Token(collateralAddress);
    }

    function getCollateral() public view returns (address) {
        console2.log("Collateral: ", address(collateral));
        console2.log("Owner: ", owner);
        console2.log("Balance owner: ", collateral.balanceOf(owner));

        return address(collateral);
    }

    function deployFactories(
        address _owner
    ) internal returns (DeployedFactories memory factories) {
        factories.vaultFactory = new VaultFactory(_owner);
        factories.delegatorFactory = new DelegatorFactory(_owner);
        factories.slasherFactory = new SlasherFactory(_owner);
    }

    function deployRegistries() internal returns (DeployedRegistries memory registries) {
        registries.networkRegistry = new NetworkRegistry();
        registries.operatorRegistry = new OperatorRegistry();
    }

    function deployServices(
        DeployedFactories memory factories,
        DeployedRegistries memory registries
    ) internal returns (DeployedServices memory services) {
        services.operatorMetadataService = new MetadataService(address(registries.operatorRegistry));
        services.networkMetadataService = new MetadataService(address(registries.networkRegistry));
        services.networkMiddlewareService = new NetworkMiddlewareService(address(registries.networkRegistry));

        services.operatorVaultOptInService = new OptInService(
            address(registries.operatorRegistry), address(factories.vaultFactory), "OperatorVaultOptInService"
        );

        services.operatorNetworkOptInService = new OptInService(
            address(registries.operatorRegistry), address(registries.networkRegistry), "OperatorNetworkOptInService"
        );
    }

    function deploySymbiotic(
        address _owner
    ) private returns (SymbioticAddresses memory) {
        DeployedFactories memory factories = deployFactories(_owner != address(0) ? _owner : owner);
        DeployedRegistries memory registries = deployRegistries();
        DeployedServices memory services = deployServices(factories, registries);

        registries.networkRegistry.registerNetwork();

        vaultConfigurator = new VaultConfigurator(
            address(factories.vaultFactory), address(factories.delegatorFactory), address(factories.slasherFactory)
        );

        address vaultImpl = address(
            new Vault(
                address(factories.delegatorFactory), address(factories.slasherFactory), address(factories.vaultFactory)
            )
        );
        factories.vaultFactory.whitelist(vaultImpl);

        address vaultTokenizedImpl = address(
            new VaultTokenized(
                address(factories.delegatorFactory), address(factories.slasherFactory), address(factories.vaultFactory)
            )
        );
        factories.vaultFactory.whitelist(vaultTokenizedImpl);

        address networkRestakeDelegatorImpl = address(
            new NetworkRestakeDelegator(
                address(registries.networkRegistry),
                address(factories.vaultFactory),
                address(services.operatorVaultOptInService),
                address(services.operatorNetworkOptInService),
                address(factories.delegatorFactory),
                factories.delegatorFactory.totalTypes()
            )
        );
        factories.delegatorFactory.whitelist(networkRestakeDelegatorImpl);

        address fullRestakeDelegatorImpl = address(
            new FullRestakeDelegator(
                address(registries.networkRegistry),
                address(factories.vaultFactory),
                address(services.operatorVaultOptInService),
                address(services.operatorNetworkOptInService),
                address(factories.delegatorFactory),
                factories.delegatorFactory.totalTypes()
            )
        );
        factories.delegatorFactory.whitelist(fullRestakeDelegatorImpl);

        address operatorSpecificDelegatorImpl = address(
            new OperatorSpecificDelegator(
                address(registries.operatorRegistry),
                address(registries.networkRegistry),
                address(factories.vaultFactory),
                address(services.operatorVaultOptInService),
                address(services.operatorNetworkOptInService),
                address(factories.delegatorFactory),
                factories.delegatorFactory.totalTypes()
            )
        );
        factories.delegatorFactory.whitelist(operatorSpecificDelegatorImpl);

        address operatorNetworkSpecificDelegatorImpl = address(
            new OperatorNetworkSpecificDelegator(
                address(registries.operatorRegistry),
                address(registries.networkRegistry),
                address(factories.vaultFactory),
                address(services.operatorVaultOptInService),
                address(services.operatorNetworkOptInService),
                address(factories.delegatorFactory),
                factories.delegatorFactory.totalTypes()
            )
        );
        factories.delegatorFactory.whitelist(operatorNetworkSpecificDelegatorImpl);

        address slasherImpl = address(
            new Slasher(
                address(factories.vaultFactory),
                address(services.networkMiddlewareService),
                address(factories.slasherFactory),
                factories.slasherFactory.totalTypes()
            )
        );
        factories.slasherFactory.whitelist(slasherImpl);

        address vetoSlasherImpl = address(
            new VetoSlasher(
                address(factories.vaultFactory),
                address(services.networkMiddlewareService),
                address(registries.networkRegistry),
                address(factories.slasherFactory),
                factories.slasherFactory.totalTypes()
            )
        );
        factories.slasherFactory.whitelist(vetoSlasherImpl);

        vaultConfigurator = new VaultConfigurator(
            address(factories.vaultFactory), address(factories.delegatorFactory), address(factories.slasherFactory)
        );

        factories.vaultFactory.transferOwnership(_owner != address(0) ? _owner : owner);
        factories.delegatorFactory.transferOwnership(_owner != address(0) ? _owner : owner);
        factories.slasherFactory.transferOwnership(_owner != address(0) ? _owner : owner);

        if (!isTest) {
            console2.log("VaultFactory: ", address(factories.vaultFactory));
            console2.log("DelegatorFactory: ", address(factories.delegatorFactory));
            console2.log("SlasherFactory: ", address(factories.slasherFactory));
            console2.log("NetworkRegistry: ", address(registries.networkRegistry));
            console2.log("OperatorRegistry: ", address(registries.operatorRegistry));
            console2.log("OperatorMetadataService: ", address(services.operatorMetadataService));
            console2.log("NetworkMetadataService: ", address(services.networkMetadataService));
            console2.log("NetworkMiddlewareService: ", address(services.networkMiddlewareService));
            console2.log("OperatorVaultOptInService: ", address(services.operatorVaultOptInService));
            console2.log("OperatorNetworkOptInService: ", address(services.operatorNetworkOptInService));
            console2.log("VaultConfigurator: ", address(vaultConfigurator));
        }

        return SymbioticAddresses({
            vaultFactory: address(factories.vaultFactory),
            delegatorFactory: address(factories.delegatorFactory),
            slasherFactory: address(factories.slasherFactory),
            networkRegistry: address(registries.networkRegistry),
            operatorRegistry: address(registries.operatorRegistry),
            operatorMetadataService: address(services.operatorMetadataService),
            networkMetadataService: address(services.networkMetadataService),
            networkMiddlewareService: address(services.networkMiddlewareService),
            operatorVaultOptInService: address(services.operatorVaultOptInService),
            operatorNetworkOptInService: address(services.operatorNetworkOptInService),
            vaultImpl: vaultImpl,
            vaultTokenizedImpl: vaultTokenizedImpl,
            networkRestakeDelegatorImpl: networkRestakeDelegatorImpl,
            fullRestakeDelegatorImpl: fullRestakeDelegatorImpl,
            operatorSpecificDelegatorImpl: operatorSpecificDelegatorImpl,
            slasherImpl: slasherImpl,
            vetoSlasherImpl: vetoSlasherImpl,
            vaultConfigurator: address(vaultConfigurator)
        });
    }

    function deploy(
        address _owner
    ) public returns (SymbioticAddresses memory addresses) {
        vm.startPrank(_owner);
        isTest = true;
        addresses = deploySymbiotic(_owner);
        vm.stopPrank();
    }

    function deploySymbioticBroadcast() public returns (SymbioticAddresses memory addresses) {
        vm.startBroadcast(ownerPrivateKey);
        isTest = false;
        addresses = deploySymbiotic(address(0));
        vm.stopBroadcast();
    }

    function run(
        address _collateral
    ) external {
        setCollateral(_collateral);
        deploySymbioticBroadcast();
        deployVault = new DeployVault();

        deployVault.deployTestVaults(
            address(vaultConfigurator), address(collateral), address(owner), VAULT_EPOCH_DURATION, VETO_DURATION
        );
    }
}
