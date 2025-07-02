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

import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {IOperatorNetworkSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorNetworkSpecificDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract DeployVault is Script {
    error DeployVault__VaultConfiguratorOrCollateralNotDeployed();

    struct VaultDeployParams {
        address vaultConfigurator;
        address owner;
        address collateral;
        uint48 epochDuration;
        bool depositWhitelist;
        uint256 depositLimit;
        VaultManager.DelegatorType delegatorIndex;
        bool withSlasher;
        VaultManager.SlasherType slasherIndex;
        uint48 vetoDuration;
        address operator;
        address network;
        address burner;
    }

    struct CreateVaultBaseParams {
        uint48 epochDuration;
        bool depositWhitelist;
        uint256 depositLimit;
        VaultManager.DelegatorType delegatorIndex;
        bool shouldBroadcast;
        address vaultConfigurator;
        address collateral;
        address owner;
        address operator;
        address network;
        address burner;
    }

    function createBaseVault(
        CreateVaultBaseParams memory params
    ) public returns (address, address, address) {
        return _createVault({
            params: params,
            withSlasher: false,
            slasherIndex: VaultManager.SlasherType.INSTANT,
            vetoDuration: 0
        });
    }

    function createSlashableVault(
        CreateVaultBaseParams memory params
    ) public returns (address, address, address) {
        return _createVault({
            params: params,
            withSlasher: true,
            slasherIndex: VaultManager.SlasherType.INSTANT,
            vetoDuration: 0
        });
    }

    function createVaultVetoed(
        CreateVaultBaseParams memory params,
        uint48 vetoDuration
    ) public returns (address, address, address) {
        return _createVault({
            params: params,
            withSlasher: true,
            slasherIndex: VaultManager.SlasherType.VETO,
            vetoDuration: vetoDuration
        });
    }

    function createTanssiVault(address vaultConfigurator, address admin, address collateral) public {
        CreateVaultBaseParams memory params = CreateVaultBaseParams({
            epochDuration: 7 days,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: true,
            vaultConfigurator: vaultConfigurator,
            collateral: collateral,
            owner: admin,
            operator: address(0),
            network: address(0),
            burner: address(0xDead)
        });
        _createVault(params, VaultManager.SlasherType.INSTANT, true, 0);
    }

    function _createVault(
        CreateVaultBaseParams memory params,
        VaultManager.SlasherType slasherIndex,
        bool withSlasher,
        uint48 vetoDuration
    ) private returns (address vault_, address delegator_, address slasher_) {
        if (address(params.vaultConfigurator) == address(0) || address(params.collateral) == address(0)) {
            revert DeployVault__VaultConfiguratorOrCollateralNotDeployed();
        }
        uint256 ownerPrivateKey =
            vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
        address owner = vm.addr(ownerPrivateKey);
        VaultDeployParams memory deployParams = VaultDeployParams({
            vaultConfigurator: address(params.vaultConfigurator),
            owner: params.owner != address(0) ? params.owner : owner,
            collateral: address(params.collateral),
            epochDuration: params.epochDuration,
            depositWhitelist: params.depositWhitelist,
            depositLimit: params.depositLimit,
            delegatorIndex: params.delegatorIndex,
            withSlasher: withSlasher,
            slasherIndex: slasherIndex,
            vetoDuration: vetoDuration,
            operator: params.operator,
            network: params.network,
            burner: params.burner
        });

        if (params.shouldBroadcast) {
            vm.startBroadcast(ownerPrivateKey);
        }
        (vault_, delegator_, slasher_) = deployVault(deployParams);
        if (params.shouldBroadcast) {
            vm.stopBroadcast();
        }
    }

    function deployVault(
        VaultDeployParams memory params
    ) public returns (address vault_, address delegator_, address slasher_) {
        bytes memory vaultParams = abi.encode(
            IVault.InitParams({
                collateral: params.collateral,
                burner: params.burner,
                epochDuration: params.epochDuration,
                depositWhitelist: params.depositWhitelist,
                isDepositLimit: params.depositLimit != 0,
                depositLimit: params.depositLimit,
                defaultAdminRoleHolder: params.owner,
                depositWhitelistSetRoleHolder: params.owner,
                depositorWhitelistRoleHolder: params.owner,
                isDepositLimitSetRoleHolder: params.owner,
                depositLimitSetRoleHolder: params.owner
            })
        );

        uint8 rolesIndex = 1;
        address[] memory networkLimitSetRoleHolders = new address[](rolesIndex);
        networkLimitSetRoleHolders[0] = params.owner;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](rolesIndex);
        operatorNetworkLimitSetRoleHolders[0] = params.owner;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](rolesIndex);
        operatorNetworkSharesSetRoleHolders[0] = params.owner;

        bytes memory delegatorParams;
        if (params.delegatorIndex == VaultManager.DelegatorType.NETWORK_RESTAKE) {
            delegatorParams = abi.encode(
                INetworkRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: params.owner,
                        hook: address(0),
                        hookSetRoleHolder: params.owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                })
            );
        } else if (params.delegatorIndex == VaultManager.DelegatorType.FULL_RESTAKE) {
            delegatorParams = abi.encode(
                IFullRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: params.owner,
                        hook: address(0),
                        hookSetRoleHolder: params.owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                })
            );
        } else if (params.delegatorIndex == VaultManager.DelegatorType.OPERATOR_SPECIFIC) {
            delegatorParams = abi.encode(
                IOperatorSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: params.owner,
                        hook: address(0),
                        hookSetRoleHolder: params.owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operator: params.operator
                })
            );
        } else if (params.delegatorIndex == VaultManager.DelegatorType.OPERATOR_NETWORK_SPECIFIC) {
            delegatorParams = abi.encode(
                IOperatorNetworkSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: params.owner,
                        hook: address(0),
                        hookSetRoleHolder: params.owner
                    }),
                    network: params.network,
                    operator: params.operator
                })
            );
        }

        bytes memory slasherParams;
        if (params.slasherIndex == VaultManager.SlasherType.INSTANT) {
            slasherParams =
                abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}));
        } else if (params.slasherIndex == VaultManager.SlasherType.VETO) {
            slasherParams = abi.encode(
                IVetoSlasher.InitParams({
                    baseParams: IBaseSlasher.BaseParams({isBurnerHook: false}),
                    vetoDuration: params.vetoDuration,
                    resolverSetEpochsDelay: 3
                })
            );
        }

        (vault_, delegator_, slasher_) = IVaultConfigurator(params.vaultConfigurator).create(
            IVaultConfigurator.InitParams({
                version: 1,
                owner: params.owner,
                vaultParams: vaultParams,
                delegatorIndex: uint64(params.delegatorIndex),
                delegatorParams: delegatorParams,
                withSlasher: params.withSlasher,
                slasherIndex: uint64(params.slasherIndex),
                slasherParams: slasherParams
            })
        );
    }

    function deployTestVaults(
        address vaultConfigurator,
        address collateral,
        address owner,
        uint48 vaultEpochDuration,
        uint48 vetoDuration
    )
        public
        returns (
            HelperConfig.VaultTrifecta memory vault,
            HelperConfig.VaultTrifecta memory vaultSlashable,
            HelperConfig.VaultTrifecta memory vaultVetoed
        )
    {
        CreateVaultBaseParams memory params = CreateVaultBaseParams({
            epochDuration: vaultEpochDuration,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: true,
            vaultConfigurator: vaultConfigurator,
            collateral: collateral,
            owner: owner,
            operator: address(0),
            network: address(0),
            burner: address(0xDead)
        });

        (address vault_, address delegator, address slasher) = createBaseVault(params);
        vault = HelperConfig.VaultTrifecta({vault: vault_, delegator: delegator, slasher: slasher});

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator);
        console2.log("Slasher: ", slasher);

        (vault_, delegator, slasher) = createSlashableVault(params);
        vaultSlashable = HelperConfig.VaultTrifecta({vault: vault_, delegator: delegator, slasher: slasher});
        console2.log("VaultSlashable: ", vault_);
        console2.log("DelegatorSlashable: ", delegator);
        console2.log("SlasherSlashable: ", slasher);

        params.delegatorIndex = VaultManager.DelegatorType.FULL_RESTAKE;

        (vault_, delegator, slasher) = createVaultVetoed(params, vetoDuration);
        vaultVetoed = HelperConfig.VaultTrifecta({vault: vault_, delegator: delegator, slasher: slasher});
        console2.log("VaultVetoed: ", vault_);
        console2.log("DelegatorVetoed: ", delegator);
        console2.log("SlasherVetoed: ", slasher);
    }
}
