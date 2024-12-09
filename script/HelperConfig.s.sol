// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {console2, Script} from "forge-std/Script.sol";
import {DeploySymbiotic} from "./DeploySymbiotic.s.sol";

contract HelperConfig is Script {
    NetworkConfig public activeNetworkConfig;

    struct NetworkConfig {
        address vaultConfigurator;
        address operatorRegistry;
        address networkRegistry;
        address vaultRegistry;
        address operatorNetworkOptIn;
        address operatorVaultOptInService;
        address networkMiddlewareService;
        address collateral;
        address stETH;
    }

    uint256 public DEFAULT_ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    constructor() {
        if (block.chainid == 31_337) {
            activeNetworkConfig = getAnvilEthConfig();
        } else {
            activeNetworkConfig = getChainConfig();
        }
    }

    function getChainConfig() public view returns (NetworkConfig memory networkConfig) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/chain_data.json");
        string memory json = vm.readFile(path);

        //! Make sure chainid is present in the json or this will just revert without giving any information
        uint256 chainId = block.chainid;
        string memory jsonPath = string.concat("$.", vm.toString(chainId));

        // Parse based on chainId
        address vaultConfiguratorAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".vaultConfigurator")), (address));
        address operatorRegistryAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorRegistry")), (address));
        address networkRegistryAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".networkRegistry")), (address));
        address vaultRegistryAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".vaultFactory")), (address));
        address operatorNetworkOptInAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorNetworkOptInService")), (address));
        address operatorVaultOptInAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorVaultOptInService")), (address));
        address networkMiddlewareAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".networkMiddlewareService")), (address));
        address defaultCollateralFactoryAddress =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".defaultCollateralFactory")), (address));
        address stETHAddress = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".stETH")), (address));

        networkConfig = NetworkConfig({
            vaultConfigurator: vaultConfiguratorAddress,
            operatorRegistry: operatorRegistryAddress,
            networkRegistry: networkRegistryAddress,
            vaultRegistry: vaultRegistryAddress,
            operatorNetworkOptIn: operatorNetworkOptInAddress,
            operatorVaultOptInService: operatorVaultOptInAddress,
            networkMiddlewareService: networkMiddlewareAddress,
            collateral: defaultCollateralFactoryAddress,
            stETH: stETHAddress
        });
    }

    function getAnvilEthConfig() public returns (NetworkConfig memory networkConfig) {
        DeploySymbiotic deploySymbiotic = new DeploySymbiotic();

        DeploySymbiotic.SymbioticAddresses memory symbioticAddresses = deploySymbiotic.deploySymbioticBroadcast();

        networkConfig = NetworkConfig({
            vaultConfigurator: symbioticAddresses.vaultConfigurator,
            operatorRegistry: symbioticAddresses.operatorRegistry,
            networkRegistry: symbioticAddresses.networkRegistry,
            vaultRegistry: symbioticAddresses.vaultFactory,
            operatorNetworkOptIn: symbioticAddresses.operatorNetworkOptInService,
            operatorVaultOptInService: symbioticAddresses.operatorVaultOptInService,
            networkMiddlewareService: symbioticAddresses.networkMiddlewareService,
            collateral: address(deploySymbiotic.collateral()),
            stETH: address(0)
        });
    }
}
