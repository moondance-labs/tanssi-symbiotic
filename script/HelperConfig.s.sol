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
    TokensConfig public activeTokensConfig;
    VaultsConfig public activeVaultsConfig;

    struct NetworkConfig {
        address vaultConfigurator;
        address operatorRegistry;
        address networkRegistry;
        address vaultRegistry;
        address operatorNetworkOptIn;
        address operatorVaultOptInService;
        address networkMiddlewareService;
        address collateral;
        address readHelper;
    }

    struct TokensConfig {
        address wstETH;
        address rETH;
        address swETH;
        address wBETH;
        address LsETH;
        address cbETH;
    }

    struct VaultTrifecta {
        address vault;
        address delegator;
        address slasher;
    }

    struct VaultsConfig {
        VaultTrifecta mevRestakedETH;
        VaultTrifecta mevCapitalETH;
        VaultTrifecta hashKeyCloudETH;
        VaultTrifecta renzoRestakedETH;
        VaultTrifecta re7LabsETH;
        VaultTrifecta re7LabsRestakingETH;
        VaultTrifecta cp0xLrtETH;
        VaultTrifecta gauntletRestakedWstETH;
        VaultTrifecta gauntletRestakedSwETH;
        VaultTrifecta gauntletRestakedRETH;
        VaultTrifecta gauntletRestakedWBETH;
    }
    // VaultTrifecta etherfiwstETH;
    // VaultTrifecta restakedLsETHVault;

    uint256 public DEFAULT_ANVIL_PRIVATE_KEY = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;

    constructor() {
        if (block.chainid == 31_337) {
            (activeNetworkConfig, activeTokensConfig, activeVaultsConfig) = getAnvilEthConfig();
        } else {
            (activeNetworkConfig, activeTokensConfig, activeVaultsConfig) = getChainConfig();
        }
    }

    function getActiveVaultsConfig() external view returns (VaultsConfig memory) {
        return activeVaultsConfig;
    }

    function getChainConfig()
        public
        view
        returns (NetworkConfig memory networkConfig, TokensConfig memory tokensConfig, VaultsConfig memory vaultsConfig)
    {
        string memory root = vm.projectRoot();
        // TODO: load from chain-addresses/tanssi.json
        string memory path = string.concat(root, "/script/chain_data.json");
        string memory json = vm.readFile(path);

        //! Make sure chainid is present in the json or this will just revert without giving any information
        uint256 chainId = block.chainid;
        // Parse based on chainId
        string memory jsonPath = string.concat("$.", vm.toString(chainId));

        networkConfig.vaultConfigurator =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".vaultConfigurator")), (address));
        networkConfig.operatorRegistry =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorRegistry")), (address));
        networkConfig.networkRegistry =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".networkRegistry")), (address));

        networkConfig.vaultRegistry =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".vaultFactory")), (address));

        networkConfig.operatorNetworkOptIn =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorNetworkOptInService")), (address));
        networkConfig.operatorVaultOptInService =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorVaultOptInService")), (address));
        networkConfig.networkMiddlewareService =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".networkMiddlewareService")), (address));

        networkConfig.collateral =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".defaultCollateralFactory")), (address));
        networkConfig.readHelper = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".readHelper")), (address));
        tokensConfig.wstETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".wstETHCollateral")), (address));
        if (chainId == 1) {
            tokensConfig.rETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".rETHCollateral")), (address));
            tokensConfig.swETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".swETHCollateral")), (address));
            tokensConfig.wBETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".wBETHCollateral")), (address));
            tokensConfig.LsETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".LsETHCollateral")), (address));
            tokensConfig.cbETH = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".cbETHCollateral")), (address));
            vaultsConfig.mevRestakedETH = _loadVaultTrifectaData(json, jsonPath, ".mevRestakedETH");
            vaultsConfig.mevCapitalETH = _loadVaultTrifectaData(json, jsonPath, ".mevCapitalETH");
            vaultsConfig.hashKeyCloudETH = _loadVaultTrifectaData(json, jsonPath, ".hashKeyCloudETH");
            vaultsConfig.renzoRestakedETH = _loadVaultTrifectaData(json, jsonPath, ".renzoRestakedETH");
            vaultsConfig.re7LabsETH = _loadVaultTrifectaData(json, jsonPath, ".re7LabsETH");
            vaultsConfig.cp0xLrtETH = _loadVaultTrifectaData(json, jsonPath, ".cp0xLrtETH");
            // vaultsConfig.etherfiwstETH = _loadVaultTrifectaData(json, jsonPath, ".etherfiwstETH");
            // vaultsConfig.restakedLsETHVault = _loadVaultTrifectaData(json, jsonPath, ".restakedLsETHVault");
            vaultsConfig.gauntletRestakedWstETH = _loadVaultTrifectaData(json, jsonPath, ".gauntletRestakedWstETH");
            vaultsConfig.re7LabsRestakingETH = _loadVaultTrifectaData(json, jsonPath, ".re7LabsRestakingETH");

            // swETH vaults
            vaultsConfig.gauntletRestakedSwETH = _loadVaultTrifectaData(json, jsonPath, ".gauntletRestakedSwETH");

            // rETH vaults
            vaultsConfig.gauntletRestakedRETH = _loadVaultTrifectaData(json, jsonPath, ".gauntletRestakedRETH");

            // wBETH vaults
            vaultsConfig.gauntletRestakedWBETH = _loadVaultTrifectaData(json, jsonPath, ".gauntletRestakedWBETH");
        }
    }

    function _loadVaultTrifectaData(
        string memory json,
        string memory jsonPath,
        string memory collateral
    ) private pure returns (VaultTrifecta memory vaultTrifecta) {
        vaultTrifecta.vault =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, string.concat(collateral, "Vault"))), (address));
        vaultTrifecta.delegator =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, string.concat(collateral, "Delegator"))), (address));
        vaultTrifecta.slasher =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, string.concat(collateral, "Slasher"))), (address));
    }

    function getAnvilEthConfig()
        public
        returns (NetworkConfig memory networkConfig, TokensConfig memory tokensConfig, VaultsConfig memory vaultConfig)
    {
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
            readHelper: address(0)
        });

        tokensConfig = TokensConfig({
            wstETH: address(0),
            rETH: address(0),
            swETH: address(0),
            wBETH: address(0),
            LsETH: address(0),
            cbETH: address(0)
        });
    }
}
