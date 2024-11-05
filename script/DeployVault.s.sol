// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {IMigratablesFactory} from "@symbiotic/src/interfaces/common/IMigratablesFactory.sol";
import {IVault} from "@symbiotic/src/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/src/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/src/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/src/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/src/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {IBaseSlasher} from "@symbiotic/src/interfaces/slasher/IBaseSlasher.sol";
import {ISlasher} from "@symbiotic/src/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/src/interfaces/slasher/IVetoSlasher.sol";

contract DeployVault is Script {
    function deployVault(
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
    ) public returns (address vault_, address delegator_, address slasher_) {
        bytes memory vaultParams = abi.encode(
            IVault.InitParams({
                collateral: address(collateral),
                burner: address(0xdEaD),
                epochDuration: epochDuration,
                depositWhitelist: depositWhitelist,
                isDepositLimit: depositLimit != 0,
                depositLimit: depositLimit,
                defaultAdminRoleHolder: owner,
                depositWhitelistSetRoleHolder: owner,
                depositorWhitelistRoleHolder: owner,
                isDepositLimitSetRoleHolder: owner,
                depositLimitSetRoleHolder: owner
            })
        );

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = owner;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = owner;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = owner;

        bytes memory delegatorParams;
        if (delegatorIndex == 0) {
            delegatorParams = abi.encode(
                INetworkRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: address(0),
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                })
            );
        } else if (delegatorIndex == 1) {
            delegatorParams = abi.encode(
                IFullRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: address(0),
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                })
            );
        } else if (delegatorIndex == 2) {
            delegatorParams = abi.encode(
                IOperatorSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: owner,
                        hook: address(0),
                        hookSetRoleHolder: owner
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operator: owner
                })
            );
        }

        bytes memory slasherParams;
        if (slasherIndex == 0) {
            slasherParams =
                abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}));
        } else if (slasherIndex == 1) {
            slasherParams = abi.encode(
                IVetoSlasher.InitParams({
                    baseParams: IBaseSlasher.BaseParams({isBurnerHook: false}),
                    vetoDuration: vetoDuration,
                    resolverSetEpochsDelay: 3
                })
            );
        }

        (vault_, delegator_, slasher_) = IVaultConfigurator(vaultConfigurator).create(
            IVaultConfigurator.InitParams({
                version: 1,
                owner: owner,
                vaultParams: vaultParams,
                delegatorIndex: delegatorIndex,
                delegatorParams: delegatorParams,
                withSlasher: withSlasher,
                slasherIndex: slasherIndex,
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

        (address vault_, address delegator_, address slasher_) = deployVault(
            vaultConfigurator,
            owner,
            collateral,
            epochDuration,
            depositWhitelist,
            depositLimit,
            delegatorIndex,
            withSlasher,
            slasherIndex,
            vetoDuration
        );

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);

        vm.stopBroadcast();
    }
}
