// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {Middleware} from "src/middleware/Middleware.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";

contract Setup is Script {
    struct SetupParams {
        address network; // Choose a random network
        address owner; // Choose an owner
        uint48 epochDuration; // 1
        address vaultFactoryAddress;
        address delegatorFactoryAddress;
        address slasherFactoryAddress;
        address[] vaults; // addresses of vaults
        address[] operators; // addresses of operators
        bytes32[] keys; // keys of operators
        address operatorRegistry; // 0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9
        address vaultRegistry; //0x5FbDB2315678afecb367f032d93F642f64180aa3
        address operatorNetworkOptIn; // 0x8A791620dd6260079BF849Dc5567aDC3F2FdC31
    }

    function run(
        SetupParams memory params
    ) external {
        require(params.operators.length == params.keys.length, "inconsistent length");
        vm.startBroadcast();

        uint48 minSlashingWindow = params.epochDuration; // we dont use this

        VaultFactory vaultFactory = VaultFactory(params.vaultFactoryAddress);
        DelegatorFactory delegatorFactory = DelegatorFactory(params.delegatorFactoryAddress);
        SlasherFactory slasherFactory = SlasherFactory(params.slasherFactoryAddress);

        address vaultImpl =
            address(new Vault(address(delegatorFactory), address(slasherFactory), address(vaultFactory)));
        vaultFactory.whitelist(vaultImpl);

        Middleware middleware = new Middleware(
            params.network,
            params.operatorRegistry,
            params.vaultRegistry,
            params.operatorNetworkOptIn,
            params.owner,
            params.epochDuration,
            minSlashingWindow
        );

        for (uint256 i = 0; i < params.vaults.length; ++i) {
            middleware.registerVault(params.vaults[i]);
        }

        for (uint256 i = 0; i < params.operators.length; ++i) {
            middleware.registerOperator(params.operators[i], params.keys[i]);
        }

        vm.stopBroadcast();
    }
}
