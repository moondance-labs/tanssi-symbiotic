// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {Middleware} from "src/middleware/Middleware.sol";

import {DeployTanssiEcosystem} from "./DeployTanssiEcosystem.s.sol";
import {Token} from "../test/mocks/Token.sol";

contract DeployTanssiVaults is Script {
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

    DeployTanssiEcosystem.VaultAddresses public vaultAddresses;
    Middleware middleware;

    function _setDelegatorConfigs() public {
        if (block.chainid == 31_337 || block.chainid == 11_155_111) {
            INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit{gas: 10_000_000}(0, MAX_NETWORK_LIMIT);
            INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit{gas: 10_000_000}(
                0, MAX_NETWORK_LIMIT
            );

            INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit{gas: 10_000_000}(
                tanssi.subnetwork(0), MAX_NETWORK_LIMIT
            );
            INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit{gas: 10_000_000}(
                tanssi.subnetwork(0), MAX_NETWORK_LIMIT
            );
        }

        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit{gas: 10_000_000}(
            0, MAX_NETWORK_LIMIT
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit{gas: 10_000_000}(
            tanssi.subnetwork(0), MAX_NETWORK_LIMIT
        );
    }

    function _registerEntitiesToMiddleware() public {
        if (block.chainid == 31_337 || block.chainid == 11_155_111) {
            middleware.registerVault{gas: 10_000_000}(vaultAddresses.vault);
            middleware.registerVault{gas: 10_000_000}(vaultAddresses.vaultVetoed);
        }
        middleware.registerVault{gas: 10_000_000}(vaultAddresses.vaultSlashable);
    }

    function run(
        address vault,
        address delegator,
        address slasher,
        address vaultSlashable,
        address delegatorSlashable,
        address slasherSlashable,
        address vaultVetoed,
        address delegatorVetoed,
        address slasherVetoed,
        address _middleware,
        address networkMiddlewareService
    ) external {
        vm.startBroadcast();
        vaultAddresses = DeployTanssiEcosystem.VaultAddresses({
            vault: vault,
            delegator: delegator,
            slasher: slasher,
            vaultSlashable: vaultSlashable,
            delegatorSlashable: delegatorSlashable,
            slasherSlashable: slasherSlashable,
            vaultVetoed: vaultVetoed,
            delegatorVetoed: delegatorVetoed,
            slasherVetoed: slasherVetoed
        });
        middleware = Middleware(_middleware);
        _setDelegatorConfigs();
        _registerEntitiesToMiddleware();
        INetworkMiddlewareService(networkMiddlewareService).setMiddleware{gas: 10_000_000}(address(middleware));
        vm.stopBroadcast();
    }
}
