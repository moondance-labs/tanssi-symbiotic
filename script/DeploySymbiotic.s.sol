// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
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
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";

import {Slasher} from "@symbiotic/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "@symbiotic/contracts/slasher/VetoSlasher.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";

import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
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
    using Subnetwork for address;

    error DeploySymbiotic__VaultConfiguratorOrCollateralNotDeployed();

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;

    // These can be hardcoded since they are anvil private keys
    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
    address public owner = vm.addr(ownerPrivateKey);

    uint256 operatorPrivateKey =
        vm.envOr("OPERATOR_PRIVATE_KEY", uint256(0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a));
    address public operator = vm.addr(operatorPrivateKey);

    VaultConfigurator vaultConfigurator;
    Token collateral;
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

    enum VaultSlashType {
        SLASH, // 0
        VETO // 1

    }

    enum DelegatorIndex {
        NETWORK_RESTAKE, // 0
        FULL_RESTAKE, // 1
        OPERATOR_SPECIFIC // 2

    }

    function setCollateral(
        address collateralAddress
    ) public {
        collateral = Token(collateralAddress);
    }

    function createBaseVault(
        uint48 epochDuration,
        bool depositWhitelist,
        uint256 depositLimit,
        DelegatorIndex delegatorIndex,
        bool shouldBroadcast
    ) public returns (address, address, address) {
        return _createVault({
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: uint8(delegatorIndex),
            withSlasher: false,
            slasherIndex: 0,
            vetoDuration: 0,
            shouldBroadcast: shouldBroadcast
        });
    }

    function createSlashableVault(
        uint48 epochDuration,
        bool depositWhitelist,
        uint256 depositLimit,
        DelegatorIndex delegatorIndex,
        bool shouldBroadcast
    ) public returns (address, address, address) {
        return _createVault({
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: uint8(delegatorIndex),
            withSlasher: true,
            slasherIndex: uint8(VaultSlashType.SLASH),
            vetoDuration: 0,
            shouldBroadcast: shouldBroadcast
        });
    }

    function createVaultVetoed(
        uint48 epochDuration,
        bool depositWhitelist,
        uint256 depositLimit,
        DelegatorIndex delegatorIndex,
        uint48 vetoDuration,
        bool shouldBroadcast
    ) public returns (address, address, address) {
        return _createVault({
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: uint8(delegatorIndex),
            withSlasher: true,
            slasherIndex: uint8(VaultSlashType.VETO),
            vetoDuration: vetoDuration, //TODO: Restrict this in order to be compliant with architecture
            shouldBroadcast: shouldBroadcast
        });
    }

    function _createVault(
        uint48 epochDuration,
        bool depositWhitelist,
        uint256 depositLimit,
        uint64 delegatorIndex,
        bool withSlasher,
        uint64 slasherIndex,
        uint48 vetoDuration,
        bool shouldBroadcast
    ) public returns (address vault_, address delegator_, address slasher_) {
        if (shouldBroadcast) {
            vm.startBroadcast(ownerPrivateKey);
        }
        if (address(vaultConfigurator) == address(0) || address(collateral) == address(0)) {
            revert DeploySymbiotic__VaultConfiguratorOrCollateralNotDeployed();
        }
        if (address(deployVault) == address(0)) {
            deployVault = new DeployVault();
        }

        DeployVault.VaultDeployParams memory params = DeployVault.VaultDeployParams({
            vaultConfigurator: address(vaultConfigurator),
            owner: owner,
            collateral: address(collateral),
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: delegatorIndex,
            withSlasher: withSlasher,
            slasherIndex: slasherIndex,
            vetoDuration: vetoDuration
        });

        (vault_, delegator_, slasher_) = deployVault.deployVault(params);
        if (shouldBroadcast) {
            vm.stopBroadcast();
        }
    }

    function getCollateral() public returns (address) {
        address contractAddress = DevOpsTools.get_most_recent_deployment("Token", block.chainid);
        collateral = Token(contractAddress);
        console2.log("Collateral: ", address(collateral));
        console2.log("Owner: ", owner);
        console2.log("Balance owner: ", collateral.balanceOf(owner));

        return contractAddress;
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
    ) public returns (SymbioticAddresses memory) {
        console2.log("msg.sender:", msg.sender, owner);
        if (_owner != address(0)) {
            vm.startPrank(_owner);
        }

        DeployedFactories memory factories = deployFactories(owner);
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

        factories.vaultFactory.transferOwnership(owner);
        factories.delegatorFactory.transferOwnership(owner);
        factories.slasherFactory.transferOwnership(owner);

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

        if (owner != address(0)) {
            vm.stopPrank();
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

    function deploySymbioticBroadcast() public returns (SymbioticAddresses memory addresses) {
        vm.startBroadcast(ownerPrivateKey);
        addresses = deploySymbiotic(address(0));
        vm.stopBroadcast();
    }

    function run() external {
        getCollateral();
        deploySymbioticBroadcast();

        (address vault, address delegator, address slasher) =
            createBaseVault(VAULT_EPOCH_DURATION, false, 0, DelegatorIndex.NETWORK_RESTAKE, true);
        console2.log("Vault: ", vault);
        console2.log("Delegator: ", delegator);
        console2.log("Slasher: ", slasher);

        (address vaultVetoed, address delegatorVetoed, address slasherVetoed) =
            createVaultVetoed(VAULT_EPOCH_DURATION, false, 0, DelegatorIndex.FULL_RESTAKE, 1 days, true);
        console2.log("VaultVetoed: ", vaultVetoed);
        console2.log("DelegatorVetoed: ", delegatorVetoed);
        console2.log("SlasherVetoed: ", slasherVetoed);
    }
}
