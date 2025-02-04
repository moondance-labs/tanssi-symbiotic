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

import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {Token} from "test/mocks/Token.sol";
import {DeployCollateral} from "./DeployCollateral.s.sol";
import {DeployVault} from "./DeployVault.s.sol";
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

    bool public isTest = false;
    VaultAddresses public vaultAddresses;
    TokensAddresses public tokensAddresses;
    EcosystemEntity public ecosystemEntities;
    ContractScripts public contractScripts;

    struct ContractScripts {
        DeployCollateral deployCollateral;
        DeployVault deployVault;
        HelperConfig helperConfig;
    }

    struct EcosystemEntity {
        Middleware middleware;
        IVaultConfigurator vaultConfigurator;
        address defaultCollateralAddress;
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

    function deployTokens(
        address owner
    ) public returns (address, address, address) {
        // if (!isTest) {
        //     vm.stopBroadcast();
        // }

        address stETH = contractScripts.deployCollateral.deployCollateral("stETH");
        console2.log(" ");
        address rETH = contractScripts.deployCollateral.deployCollateral("rETH");
        console2.log(" ");
        address wBTC = contractScripts.deployCollateral.deployCollateral("wBTC");
        console2.log(" ");

        tokensAddresses.stETHToken = Token(stETH);
        tokensAddresses.rETHToken = Token(rETH);
        tokensAddresses.wBTCToken = Token(wBTC);

        tokensAddresses.stETHToken.mint{gas: 1_000_000}(owner, 10_000 ether);
        tokensAddresses.rETHToken.mint(owner, 10_000 ether);
        tokensAddresses.wBTCToken.mint(owner, 10_000 ether);

        // vm.stopBroadcast();

        // if (!isTest) {
        //     vm.startBroadcast(ownerPrivateKey);
        // }
        return (stETH, rETH, wBTC);
        // return (stETH, address(0), address(0));
    }

    function deployVaults() public returns (VaultAddresses memory) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeployVault.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: !isTest,
            vaultConfigurator: address(ecosystemEntities.vaultConfigurator),
            collateral: ecosystemEntities.defaultCollateralAddress != address(0)
                ? ecosystemEntities.defaultCollateralAddress
                : address(tokensAddresses.stETHToken),
            owner: tanssi
        });

        if (!isTest) {
            vm.stopBroadcast();
        }

        // On real scenario we want to deploy only the slashable vault. TBD
        if (isTest || block.chainid == 31_337 || block.chainid == 11_155_111) {
            (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) =
                contractScripts.deployVault.createBaseVault(params);
            console2.log("Vault Collateral: ", IVault(vaultAddresses.vault).collateral());
            console2.log("Vault: ", vaultAddresses.vault);
            console2.log("Delegator: ", vaultAddresses.delegator);
            console2.log("Slasher: ", vaultAddresses.slasher);
            console2.log(" ");
        }

        if (block.chainid == 31_337 || block.chainid == 11_155_111) {
            params.collateral = address(tokensAddresses.rETHToken);
        }
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            contractScripts.deployVault.createSlashableVault(params);
        console2.log("VaultSlashable Collateral: ", IVault(vaultAddresses.vaultSlashable).collateral());
        console2.log("VaultSlashable: ", vaultAddresses.vaultSlashable);
        console2.log("DelegatorSlashable: ", vaultAddresses.delegatorSlashable);
        console2.log("SlasherSlashable: ", vaultAddresses.slasherSlashable);
        console2.log(" ");

        if (isTest || block.chainid == 31_337 || block.chainid == 11_155_111) {
            params.delegatorIndex = DeployVault.DelegatorIndex.FULL_RESTAKE;
            if (block.chainid == 31_337 || block.chainid == 11_155_111) {
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

    function _setDelegatorConfigs() private {
        if (block.chainid == 31_337 || block.chainid == 11_155_111 || isTest) {
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
        if (block.chainid == 31_337 || block.chainid == 11_155_111 || isTest) {
            ecosystemEntities.middleware.registerVault(vaultAddresses.vault);
            ecosystemEntities.middleware.registerVault(vaultAddresses.vaultVetoed);
        }
        ecosystemEntities.middleware.registerVault(vaultAddresses.vaultSlashable);
    }

    function _transferTokensToOperators() private {
        // vm.startBroadcast(ownerPrivateKey);
        tokensAddresses.stETHToken.transfer{gas: 1_000_000}(operator, 1000 ether);
        tokensAddresses.stETHToken.transfer{gas: 1_000_000}(operator3, 1000 ether);

        tokensAddresses.rETHToken.transfer(operator, 1000 ether);
        tokensAddresses.rETHToken.transfer(operator2, 1000 ether);
        tokensAddresses.rETHToken.transfer(operator3, 1000 ether);

        tokensAddresses.wBTCToken.transfer(operator3, 1000 ether);
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
        ) = contractScripts.helperConfig.activeNetworkConfig();

        IDefaultCollateralFactory defaultCollateralFactory;
        if (block.chainid != 31_337 && block.chainid != 11_155_111) {
            defaultCollateralFactory = IDefaultCollateralFactory(defaultCollateralFactoryAddress);
            ecosystemEntities.defaultCollateralAddress =
                defaultCollateralFactory.create(address(stETHAddress), 10_000 ether, address(0));
        }

        ecosystemEntities.vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);

        INetworkRegistry networkRegistry = INetworkRegistry(networkRegistryAddress);
        IOperatorRegistry operatorRegistry = IOperatorRegistry(operatorRegistryAddress);
        INetworkMiddlewareService networkMiddlewareService = INetworkMiddlewareService(networkMiddlewareServiceAddress);
        IOptInService operatorNetworkOptInService = IOptInService(operatorNetworkOptInServiceAddress);
        IOptInService operatorVaultOptInService = IOptInService(operatorVaultOptInServiceAddress);

        if (block.chainid == 31_337 || block.chainid == 11_155_111) {
            // Deploy simple ERC20 collateral tokens
            deployTokens(tanssi);
            _transferTokensToOperators();
        } else {
            networkRegistry.registerNetwork();
        }
        deployVaults();
        _setDelegatorConfigs();
        ecosystemEntities.middleware = new Middleware(
            tanssi,
            operatorRegistryAddress,
            vaultRegistryAddress,
            operatorNetworkOptInServiceAddress,
            tanssi,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        _registerEntitiesToMiddleware();
        networkMiddlewareService.setMiddleware(address(ecosystemEntities.middleware));

        ODefaultOperatorRewards operatorRewards =
            new ODefaultOperatorRewards(tanssi, address(networkMiddlewareService), 20);

        ecosystemEntities.middleware.setOperatorRewardsContract(address(operatorRewards));

        console2.log("VaultConfigurator: ", address(ecosystemEntities.vaultConfigurator));
        console2.log("OperatorRegistry: ", address(operatorRegistry));
        console2.log("NetworkRegistry: ", address(networkRegistry));
        console2.log("NetworkMiddlewareService: ", address(networkMiddlewareService));
        console2.log("OperatorNetworkOptInService: ", address(operatorNetworkOptInService));
        console2.log("OperatorVaultOptInService: ", address(operatorVaultOptInService));
        console2.log("DefaultCollateralFactory: ", address(defaultCollateralFactory));
        console2.log("DefaultCollateral: ", ecosystemEntities.defaultCollateralAddress);
        console2.log("Middleware: ", address(ecosystemEntities.middleware));
        console2.log("OperatorRewards: ", address(operatorRewards));
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

    function deployMiddleware(
        address networkAddress,
        address operatorRegistryAddress,
        address vaultRegistryAddress,
        address operatorNetworkOptInServiceAddress,
        address ownerAddress,
        uint48 epochDuration,
        uint48 slashingWindow
    ) external {
        vm.startBroadcast(ownerPrivateKey);
        ecosystemEntities.middleware = new Middleware(
            networkAddress,
            operatorRegistryAddress,
            vaultRegistryAddress,
            operatorNetworkOptInServiceAddress,
            ownerAddress,
            epochDuration,
            slashingWindow
        );
        vm.stopBroadcast();
    }

    function registerVault(
        address vaultAddress
    ) external {
        vm.startBroadcast(ownerPrivateKey);
        ecosystemEntities.middleware.registerVault(vaultAddress);
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
        contractScripts.helperConfig = _helperConfig;
        contractScripts.deployVault = new DeployVault();
        contractScripts.deployCollateral = new DeployCollateral();

        vm.startPrank(tanssi);
        isTest = true;
        _deploy();
        vm.stopPrank();
    }

    function run() external {
        contractScripts.helperConfig = new HelperConfig();
        contractScripts.deployVault = new DeployVault();
        contractScripts.deployCollateral = new DeployCollateral();
        vm.startBroadcast(ownerPrivateKey);
        isTest = false;
        _deploy();
        vm.stopBroadcast();
    }
}
