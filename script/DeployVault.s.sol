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

import {IMigratablesFactory} from "@symbiotic/interfaces/common/IMigratablesFactory.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";

import {DeploySymbiotic} from "./DeploySymbiotic.s.sol";

contract DeployVault is Script {
    error DeployVault__VaultConfiguratorOrCollateralNotDeployed();

    struct VaultDeployParams {
        address vaultConfigurator;
        address owner;
        address collateral;
        uint48 epochDuration;
        bool depositWhitelist;
        uint256 depositLimit;
        uint64 delegatorIndex;
        bool withSlasher;
        uint64 slasherIndex;
        uint48 vetoDuration;
        address operator;
    }

    struct CreateVaultBaseParams {
        uint48 epochDuration;
        bool depositWhitelist;
        uint256 depositLimit;
        DelegatorIndex delegatorIndex;
        bool shouldBroadcast;
        address vaultConfigurator;
        address collateral;
        address owner;
        address operator;
    }

    enum DelegatorIndex {
        NETWORK_RESTAKE, // 0
        FULL_RESTAKE, // 1
        OPERATOR_SPECIFIC, // 2
        OPERATOR_NETWORK_SPECIFIC // 3

    }

    function createBaseVault(
        CreateVaultBaseParams memory params
    ) public returns (address, address, address) {
        return _createVault({params: params, withSlasher: false, slasherIndex: 0, vetoDuration: 0});
    }

    function createSlashableVault(
        CreateVaultBaseParams memory params
    ) public returns (address, address, address) {
        return _createVault({
            params: params,
            withSlasher: true,
            slasherIndex: uint8(DeploySymbiotic.VaultSlashType.SLASH),
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
            slasherIndex: uint8(DeploySymbiotic.VaultSlashType.VETO),
            vetoDuration: vetoDuration
        });
    }

    function _createVault(
        CreateVaultBaseParams memory params,
        uint64 slasherIndex,
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
            delegatorIndex: uint64(params.delegatorIndex),
            withSlasher: withSlasher,
            slasherIndex: slasherIndex,
            vetoDuration: vetoDuration,
            operator: params.operator
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
                burner: address(0xdEaD),
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
        if (params.delegatorIndex == 0) {
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
        } else if (params.delegatorIndex == 1) {
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
        } else if (params.delegatorIndex == 2) {
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
        }

        bytes memory slasherParams;
        if (params.slasherIndex == 0) {
            slasherParams =
                abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}));
        } else if (params.slasherIndex == 1) {
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
                delegatorIndex: params.delegatorIndex,
                delegatorParams: delegatorParams,
                withSlasher: params.withSlasher,
                slasherIndex: params.slasherIndex,
                slasherParams: slasherParams
            })
        );
    }

    function deployAllVaults(
        address vaultConfigurator,
        address collateral,
        address owner,
        uint48 vaultEpochDuration
    ) public {
        CreateVaultBaseParams memory params = CreateVaultBaseParams({
            epochDuration: vaultEpochDuration,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: true,
            vaultConfigurator: vaultConfigurator,
            collateral: collateral,
            owner: owner,
            operator: address(0)
        });

        (address vault, address delegator, address slasher) = createBaseVault(params);

        console2.log("Vault: ", vault);
        console2.log("Delegator: ", delegator);
        console2.log("Slasher: ", slasher);

        (address vaultSlashable, address delegatorSlashable, address slasherSlashable) = createSlashableVault(params);
        console2.log("VaultSlashable: ", vaultSlashable);
        console2.log("DelegatorSlashable: ", delegatorSlashable);
        console2.log("SlasherSlashable: ", slasherSlashable);

        params.delegatorIndex = DelegatorIndex.FULL_RESTAKE;

        (address vaultVetoed, address delegatorVetoed, address slasherVetoed) = createVaultVetoed(params, 1 days);
        console2.log("VaultVetoed: ", vaultVetoed);
        console2.log("DelegatorVetoed: ", delegatorVetoed);
        console2.log("SlasherVetoed: ", slasherVetoed);
    }

    function run(
        address vaultConfigurator,
        address _owner,
        address collateral,
        uint48 epochDuration,
        bool depositWhitelist,
        uint256 depositLimit,
        uint64 delegatorIndex,
        bool withSlasher,
        uint64 slasherIndex,
        uint48 vetoDuration
    ) public {
        vm.startBroadcast();

        VaultDeployParams memory params = VaultDeployParams({
            vaultConfigurator: vaultConfigurator,
            owner: _owner,
            collateral: collateral,
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: delegatorIndex,
            withSlasher: withSlasher,
            slasherIndex: slasherIndex,
            vetoDuration: vetoDuration,
            operator: address(0)
        });
        (address vault_, address delegator_, address slasher_) = deployVault(params);

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);

        vm.stopBroadcast();
    }
}
