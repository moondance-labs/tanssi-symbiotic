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

        (vault_, delegator_, slasher_) = deployVault.deployVault({
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

    function deploySymbiotic(
        address _owner
    ) public returns (SymbioticAddresses memory) {
        console2.log("msg.sender:", msg.sender, owner);
        if (_owner != address(0)) {
            vm.startPrank(_owner);
        }
        VaultFactory vaultFactory = new VaultFactory(owner);
        DelegatorFactory delegatorFactory = new DelegatorFactory(owner);
        SlasherFactory slasherFactory = new SlasherFactory(owner);
        NetworkRegistry networkRegistry = new NetworkRegistry();
        OperatorRegistry operatorRegistry = new OperatorRegistry();
        MetadataService operatorMetadataService = new MetadataService(address(operatorRegistry));
        MetadataService networkMetadataService = new MetadataService(address(networkRegistry));
        NetworkMiddlewareService networkMiddlewareService = new NetworkMiddlewareService(address(networkRegistry));

        OptInService operatorVaultOptInService =
            new OptInService(address(operatorRegistry), address(vaultFactory), "OperatorVaultOptInService");
        OptInService operatorNetworkOptInService =
            new OptInService(address(operatorRegistry), address(networkRegistry), "OperatorNetworkOptInService");

        networkRegistry.registerNetwork();

        address vaultImpl =
            address(new Vault(address(delegatorFactory), address(slasherFactory), address(vaultFactory)));
        vaultFactory.whitelist(vaultImpl);

        address vaultTokenizedImpl =
            address(new VaultTokenized(address(delegatorFactory), address(slasherFactory), address(vaultFactory)));
        vaultFactory.whitelist(vaultTokenizedImpl);

        address networkRestakeDelegatorImpl = address(
            new NetworkRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(networkRestakeDelegatorImpl);

        address fullRestakeDelegatorImpl = address(
            new FullRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(fullRestakeDelegatorImpl);

        address operatorSpecificDelegatorImpl = address(
            new OperatorSpecificDelegator(
                address(operatorRegistry),
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(operatorSpecificDelegatorImpl);

        address slasherImpl = address(
            new Slasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(slasherImpl);

        address vetoSlasherImpl = address(
            new VetoSlasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(networkRegistry),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(vetoSlasherImpl);

        vaultConfigurator =
            new VaultConfigurator(address(vaultFactory), address(delegatorFactory), address(slasherFactory));

        vaultFactory.transferOwnership(owner);
        delegatorFactory.transferOwnership(owner);
        slasherFactory.transferOwnership(owner);

        console2.log("VaultFactory: ", address(vaultFactory));
        console2.log("DelegatorFactory: ", address(delegatorFactory));
        console2.log("SlasherFactory: ", address(slasherFactory));
        console2.log("NetworkRegistry: ", address(networkRegistry));
        console2.log("OperatorRegistry: ", address(operatorRegistry));
        console2.log("OperatorMetadataService: ", address(operatorMetadataService));
        console2.log("NetworkMetadataService: ", address(networkMetadataService));
        console2.log("NetworkMiddlewareService: ", address(networkMiddlewareService));
        console2.log("OperatorVaultOptInService: ", address(operatorVaultOptInService));
        console2.log("OperatorNetworkOptInService: ", address(operatorNetworkOptInService));
        console2.log("VaultConfigurator: ", address(vaultConfigurator));

        if (owner != address(0)) {
            vm.stopPrank();
        }
        return SymbioticAddresses({
            vaultFactory: address(vaultFactory),
            delegatorFactory: address(delegatorFactory),
            slasherFactory: address(slasherFactory),
            networkRegistry: address(networkRegistry),
            operatorRegistry: address(operatorRegistry),
            operatorMetadataService: address(operatorMetadataService),
            networkMetadataService: address(networkMetadataService),
            networkMiddlewareService: address(networkMiddlewareService),
            operatorVaultOptInService: address(operatorVaultOptInService),
            operatorNetworkOptInService: address(operatorNetworkOptInService),
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
