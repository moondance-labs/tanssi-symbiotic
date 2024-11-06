// SPDX-License-Identifier: MIT
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

contract DeployVault is Script {
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

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = params.owner;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = params.owner;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
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
                    operator: params.owner
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

    function run(
        address vaultConfigurator,
        address owner,
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
            owner: owner,
            collateral: collateral,
            epochDuration: epochDuration,
            depositWhitelist: depositWhitelist,
            depositLimit: depositLimit,
            delegatorIndex: delegatorIndex,
            withSlasher: withSlasher,
            slasherIndex: slasherIndex,
            vetoDuration: vetoDuration
        });
        (address vault_, address delegator_, address slasher_) = deployVault(params);

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);

        vm.stopBroadcast();
    }
}
