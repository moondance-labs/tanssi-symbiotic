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
        address readHelper;
    }

    uint256 public DEFAULT_ANVIL_PRIVATE_KEY = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;

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
        address readHelperAddress = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".readHelper")), (address));
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
            stETH: stETHAddress,
            readHelper: readHelperAddress
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
            stETH: address(0),
            readHelper: address(0)
        });
    }
}
