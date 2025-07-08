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

import {Script} from "forge-std/Script.sol";
import {DeploySymbiotic} from "./DeploySymbiotic.s.sol";

contract HelperConfig is Script {
    struct Entities {
        address admin;
        address tanssi;
        address gateway;
        address forwarder;
        address middleware;
        address operatorRewards;
        address rewardsToken;
    }

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

    struct FullTokenConfig {
        CollateralData wstETH;
        CollateralData rETH;
        CollateralData swETH;
        CollateralData wBETH;
        CollateralData LsETH;
        CollateralData cbETH;
    }

    struct VaultTrifecta {
        address vault;
        address delegator;
        address slasher;
    }

    struct VaultsConfigA {
        VaultData mevRestakedETH; // MEV Capital restaked ETH
        VaultData mevCapitalETH; // MEV Capital wstETH Vault
        VaultData hashKeyCloudETH; // HashKey Cloud Restaked ETH
        VaultData renzoRestakedETH; // Renzo Restaked LST
        VaultData re7LabsETH; // Re7 Labs LRT Vault
        VaultData re7LabsRestakingETH; // Restaking Vault ETH [all Networks]
        VaultData cp0xLrtETH; // cp0x LRT Conservative Vault
        VaultData etherfiwstETH; // Ether.fi - wstETH
        VaultData restakedLsETHVault; // Restaked LsETH Vault
        VaultData opslayer; // Opslayer Vault
    }

    struct VaultsConfigB {
        VaultData gauntletRestakedWstETH; // Gauntlet Restaked wstETH
        VaultData gauntletRestakedSwETH; // Gauntlet Restaked swETH
        VaultData gauntletRestakedRETH; // Gauntlet Restaked rETH
        VaultData gauntletRestakedWBETH; // Gauntlet Restaked wBETH
        VaultData gauntletRestakedcBETH; // Gauntlet Restaked cbETH
    }

    struct CollateralData {
        address collateral;
        address oracle;
        string name;
        string symbol;
    }

    struct VaultData {
        string name;
        address vault;
        address delegator;
        address slasher;
        address collateral;
        address stakerRewards;
    }

    struct OperatorData {
        string name;
        address evmAddress;
        bytes32 operatorKey;
        address[] vaults;
        uint256[] powers; // Indexes match vaults array
    }

    struct OperatorConfig {
        OperatorData operator1PierTwo;
        OperatorData operator2P2P;
        OperatorData operator3Nodeinfra;
        OperatorData operator4Blockscape;
        OperatorData operator5QuantNode;
        OperatorData operator6NodeMonster;
        OperatorData operator7BlockBones;
        OperatorData operator8CP0XStakrspace;
        OperatorData operator9HashkeyCloud;
        OperatorData operator10Alchemy;
        OperatorData operator11Opslayer;
    }

    Entities public activeEntities;
    NetworkConfig public activeNetworkConfig;
    TokensConfig public activeTokensConfig;
    FullTokenConfig public activeFullTokenConfig;
    VaultsConfigA public activeVaultsConfigA;
    VaultsConfigB public activeVaultsConfigB;
    OperatorConfig public activeOperatorConfig;

    uint256 public PRIVATE_KEY =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));

    constructor() {
        if (block.chainid == 1 || block.chainid == 11_155_111) {
            (
                activeEntities,
                activeNetworkConfig,
                activeTokensConfig,
                activeFullTokenConfig,
                activeVaultsConfigA,
                activeVaultsConfigB,
                activeOperatorConfig
            ) = getChainConfig();
        } else {
            // Other configurations can remain empty
            activeNetworkConfig = getAnvilEthConfig();
            activeEntities.tanssi = vm.addr(PRIVATE_KEY);
            activeEntities.admin = activeEntities.tanssi;
        }
    }

    function getChainConfig()
        public
        view
        returns (
            Entities memory entities,
            NetworkConfig memory networkConfig,
            TokensConfig memory tokensConfig,
            FullTokenConfig memory fullTokenConfig,
            VaultsConfigA memory vaultsConfigA,
            VaultsConfigB memory vaultsConfigB,
            OperatorConfig memory operatorConfig
        )
    {
        (string memory json, string memory jsonPath) = getJsonAndPathForChain();

        entities.admin = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".admin")), (address));
        entities.tanssi = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".tanssi")), (address));
        entities.gateway = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".gateway")), (address));
        entities.forwarder = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".forwarder")), (address));
        entities.middleware = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".middleware")), (address));
        entities.operatorRewards =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".operatorRewards")), (address));
        entities.rewardsToken = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".rewardsToken")), (address));

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
        networkConfig.readHelper =
            abi.decode(vm.parseJson(json, string.concat(jsonPath, ".middlewareReader")), (address));

        if (block.chainid == 1) {
            uint256 totalCollaterals =
                abi.decode(vm.parseJson(json, string.concat(jsonPath, ".totalCollaterals")), (uint256));
            for (uint256 i = 0; i < totalCollaterals; i++) {
                CollateralData memory collateral =
                    _loadCollateral(json, string.concat(jsonPath, ".collaterals[", vm.toString(i), "]"));
                _assignCollateral(collateral, tokensConfig, fullTokenConfig);
            }

            uint256 totalVaults = abi.decode(vm.parseJson(json, string.concat(jsonPath, ".totalVaults")), (uint256));
            for (uint256 i = 0; i < totalVaults; i++) {
                VaultData memory vault = _loadVault(json, string.concat(jsonPath, ".vaults[", vm.toString(i), "]"));
                _assignVault(vault, vaultsConfigA, vaultsConfigB);
            }

            uint256 totalOperators =
                abi.decode(vm.parseJson(json, string.concat(jsonPath, ".totalOperators")), (uint256));
            for (uint256 i = 0; i < totalOperators; i++) {
                OperatorData memory operator =
                    _loadOperator(json, string.concat(jsonPath, ".operators[", vm.toString(i), "]"));
                _assignOperator(operator, operatorConfig);
            }
        } else {
            networkConfig.collateral =
                abi.decode(vm.parseJson(json, string.concat(jsonPath, ".collaterals[0].address")), (address));
            tokensConfig.wstETH = networkConfig.collateral;

            if (block.chainid == 11_155_111) {
                VaultData memory vault = _loadVault(json, string.concat(jsonPath, ".vaults[0]"));
                _assignVault(vault, vaultsConfigA, vaultsConfigB);
                OperatorData memory operator = _loadOperator(json, string.concat(jsonPath, ".operators[0]"));
                _assignOperator(operator, operatorConfig);
            }
        }
    }

    function _loadCollateral(string memory json, string memory path) private pure returns (CollateralData memory) {
        // Trying to decode the full dictionary as a struct won't work, even if docs suggest it. I suspect it's due to dictionary keys not guaranteed to be in order.
        string memory name = abi.decode(vm.parseJson(json, string.concat(path, ".name")), (string));
        string memory symbol = abi.decode(vm.parseJson(json, string.concat(path, ".symbol")), (string));
        address collateral = abi.decode(vm.parseJson(json, string.concat(path, ".address")), (address));
        address oracle = abi.decode(vm.parseJson(json, string.concat(path, ".oracle")), (address));
        return CollateralData({name: name, symbol: symbol, collateral: collateral, oracle: oracle});
    }

    function _loadVault(string memory json, string memory path) private pure returns (VaultData memory) {
        string memory name = abi.decode(vm.parseJson(json, string.concat(path, ".name")), (string));
        address vault = abi.decode(vm.parseJson(json, string.concat(path, ".vault")), (address));
        address delegator = abi.decode(vm.parseJson(json, string.concat(path, ".delegator")), (address));
        address slasher = abi.decode(vm.parseJson(json, string.concat(path, ".slasher")), (address));
        address collateral = abi.decode(vm.parseJson(json, string.concat(path, ".collateral")), (address));
        address stakerRewards = abi.decode(vm.parseJson(json, string.concat(path, ".stakerRewards")), (address));
        return VaultData({
            name: name,
            vault: vault,
            delegator: delegator,
            slasher: slasher,
            collateral: collateral,
            stakerRewards: stakerRewards
        });
    }

    function _loadOperator(
        string memory json,
        string memory path
    ) private pure returns (OperatorData memory operator) {
        string memory name = abi.decode(vm.parseJson(json, string.concat(path, ".name")), (string));
        address evmAddress = abi.decode(vm.parseJson(json, string.concat(path, ".evmAddress")), (address));
        bytes32 operatorKey = abi.decode(vm.parseJson(json, string.concat(path, ".operatorKey")), (bytes32));

        operator.name = name;
        operator.evmAddress = evmAddress;
        operator.operatorKey = operatorKey;
    }

    function _assignCollateral(
        CollateralData memory collateral,
        TokensConfig memory tokensConfig,
        FullTokenConfig memory fullTokenConfig
    ) private pure {
        if (_sameString(collateral.symbol, "rETH")) {
            tokensConfig.rETH = collateral.collateral;
            fullTokenConfig.rETH = collateral;
        } else if (_sameString(collateral.symbol, "swETH")) {
            tokensConfig.swETH = collateral.collateral;
            fullTokenConfig.swETH = collateral;
        } else if (_sameString(collateral.symbol, "wBETH")) {
            tokensConfig.wBETH = collateral.collateral;
            fullTokenConfig.wBETH = collateral;
        } else if (_sameString(collateral.symbol, "LsETH")) {
            tokensConfig.LsETH = collateral.collateral;
            fullTokenConfig.LsETH = collateral;
        } else if (_sameString(collateral.symbol, "cbETH")) {
            tokensConfig.cbETH = collateral.collateral;
            fullTokenConfig.cbETH = collateral;
        } else if (_sameString(collateral.symbol, "wstETH")) {
            tokensConfig.wstETH = collateral.collateral;
            fullTokenConfig.wstETH = collateral;
        }
    }

    function _assignVault(
        VaultData memory vault,
        VaultsConfigA memory vaultsConfigA,
        VaultsConfigB memory vaultsConfigB
    ) private pure {
        if (_sameString(vault.name, "MEV Capital restaked ETH")) {
            vaultsConfigA.mevRestakedETH = vault;
        } else if (_sameString(vault.name, "MEV Capital wstETH Vault")) {
            vaultsConfigA.mevCapitalETH = vault;
        } else if (_sameString(vault.name, "Hashkey Cloud")) {
            vaultsConfigA.hashKeyCloudETH = vault;
        } else if (_sameString(vault.name, "Renzo restaked LST")) {
            vaultsConfigA.renzoRestakedETH = vault;
        } else if (_sameString(vault.name, "Re7 Labs LRT Vault")) {
            vaultsConfigA.re7LabsETH = vault;
        } else if (_sameString(vault.name, "Re7 Restaking Vault ETH [All Networks]")) {
            vaultsConfigA.re7LabsRestakingETH = vault;
        } else if (_sameString(vault.name, "cp0x LRT conservative vault")) {
            vaultsConfigA.cp0xLrtETH = vault;
        } else if (_sameString(vault.name, "Ether fi wstETH")) {
            vaultsConfigA.etherfiwstETH = vault;
        } else if (_sameString(vault.name, "Restaked LsETH Vault (Liquid Collective)")) {
            vaultsConfigA.restakedLsETHVault = vault;
        } else if (_sameString(vault.name, "Opslayer Vault")) {
            vaultsConfigA.opslayer = vault;
        } else if (_sameString(vault.name, "Gauntlet restaked wstETH")) {
            vaultsConfigB.gauntletRestakedWstETH = vault;
        } else if (_sameString(vault.name, "Gauntlet restaked swETH")) {
            vaultsConfigB.gauntletRestakedSwETH = vault;
        } else if (_sameString(vault.name, "Gauntlet restaked rETH")) {
            vaultsConfigB.gauntletRestakedRETH = vault;
        } else if (_sameString(vault.name, "Gauntlet restaked wBETH")) {
            vaultsConfigB.gauntletRestakedWBETH = vault;
        } else if (_sameString(vault.name, "Gauntlet restaked cbETH")) {
            vaultsConfigB.gauntletRestakedcBETH = vault;
        }
    }

    function _assignOperator(OperatorData memory operator, OperatorConfig memory operatorConfig) private pure {
        if (_sameString(operator.name, "Pier Two")) {
            operatorConfig.operator1PierTwo = operator;
        } else if (_sameString(operator.name, "P2P")) {
            operatorConfig.operator2P2P = operator;
        } else if (_sameString(operator.name, "Nodeinfra")) {
            operatorConfig.operator3Nodeinfra = operator;
        } else if (_sameString(operator.name, "Blockscape")) {
            operatorConfig.operator4Blockscape = operator;
        } else if (_sameString(operator.name, "Quant Node")) {
            operatorConfig.operator5QuantNode = operator;
        } else if (_sameString(operator.name, "Node Monster")) {
            operatorConfig.operator6NodeMonster = operator;
        } else if (_sameString(operator.name, "Block n Bones")) {
            operatorConfig.operator7BlockBones = operator;
        } else if (_sameString(operator.name, "CP0X by Stakr.space")) {
            operatorConfig.operator8CP0XStakrspace = operator;
        } else if (_sameString(operator.name, "Hashkey Cloud")) {
            operatorConfig.operator9HashkeyCloud = operator;
        } else if (_sameString(operator.name, "Alchemy")) {
            operatorConfig.operator10Alchemy = operator;
        } else if (_sameString(operator.name, "Opslayer")) {
            operatorConfig.operator11Opslayer = operator;
        }
    }

    function _sameString(string memory a, string memory b) private pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
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
            readHelper: address(0)
        });
    }

    function getJsonAndPathForChain() public view returns (string memory json, string memory jsonPath) {
        string memory root = vm.projectRoot();
        uint256 chainId = block.chainid;

        if (chainId == 1) {
            json = vm.readFile(string.concat(root, "/contract-addresses/tanssi.json"));
            jsonPath = "$";
        } else if (chainId == 11_155_111) {
            json = vm.readFile(string.concat(root, "/contract-addresses/stagelight.json"));
            jsonPath = "$";
        }
    }
}
