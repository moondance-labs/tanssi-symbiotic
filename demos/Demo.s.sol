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
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {VaultConfigurator} from "@symbiotic/contracts/VaultConfigurator.sol";
import {OperatorRegistry} from "@symbiotic/contracts/OperatorRegistry.sol";
import {NetworkRegistry} from "@symbiotic/contracts/NetworkRegistry.sol";
import {OptInService} from "@symbiotic/contracts/service/OptInService.sol";
import {Vault} from "@symbiotic/contracts/vault/Vault.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {DeployCollateral} from "../DeployCollateral.s.sol";
import {DeployVault} from "../DeployVault.s.sol";
import {DeploySymbiotic} from "../DeploySymbiotic.s.sol";

import {Token} from "test/mocks/Token.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

contract Demo is Script {
    using Subnetwork for address;

    struct VaultAddresses {
        address vault;
        address delegator;
        address slasher;
        address vaultSlashable;
        address delegatorSlashable;
        address slasherSlashable;
        address vaultVetoed;
        address delegatorVetoed;
        address slasherVetoed;
    }

    uint48 public constant VAULT_EPOCH_DURATION = 8 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
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

    DeployCollateral deployCollateral;
    DeployVault deployVault;
    VaultConfigurator vaultConfigurator;
    OperatorRegistry operatorRegistry;
    NetworkRegistry networkRegistry;
    OptInService operatorNetworkOptInService;
    OptInService operatorVaultOptInService;

    Middleware middleware;
    Token stETHToken;
    Token rETHToken;
    Token wBTCToken;

    VaultAddresses public vaultAddresses;

    function deployTokens() public returns (address, address, address) {
        address stETH = deployCollateral.deployCollateralBroadcast("stETH");
        console2.log(" ");
        address rETH = deployCollateral.deployCollateralBroadcast("rETH");
        console2.log(" ");
        address wBTC = deployCollateral.deployCollateralBroadcast("wBTC");
        console2.log(" ");

        stETHToken = Token(stETH);
        rETHToken = Token(rETH);
        wBTCToken = Token(wBTC);

        vm.startBroadcast(ownerPrivateKey);
        stETHToken.transfer(operator, 1000 ether);
        stETHToken.transfer(operator3, 1000 ether);

        rETHToken.transfer(operator, 1000 ether);
        rETHToken.transfer(operator2, 1000 ether);
        rETHToken.transfer(operator3, 1000 ether);

        wBTCToken.transfer(operator3, 1000 ether);
        vm.stopBroadcast();

        return (stETH, rETH, wBTC);
    }

    function deployVaults() public returns (VaultAddresses memory) {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: true,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(stETHToken),
            owner: tanssi,
            operator: address(0)
        });

        (vaultAddresses.vault, vaultAddresses.delegator, vaultAddresses.slasher) = deployVault.createBaseVault(params);
        console2.log("Vault Collateral: ", Vault(vaultAddresses.vault).collateral());
        console2.log("Vault: ", vaultAddresses.vault);
        console2.log("Delegator: ", vaultAddresses.delegator);
        console2.log("Slasher: ", vaultAddresses.slasher);
        console2.log(" ");

        params.collateral = address(rETHToken);
        (vaultAddresses.vaultSlashable, vaultAddresses.delegatorSlashable, vaultAddresses.slasherSlashable) =
            deployVault.createSlashableVault(params);
        console2.log("VaultSlashable Collateral: ", Vault(vaultAddresses.vaultSlashable).collateral());
        console2.log("VaultSlashable: ", vaultAddresses.vaultSlashable);
        console2.log("DelegatorSlashable: ", vaultAddresses.delegatorSlashable);
        console2.log("SlasherSlashable: ", vaultAddresses.slasherSlashable);
        console2.log(" ");

        params.delegatorIndex = VaultManager.DelegatorType.FULL_RESTAKE;
        params.collateral = address(wBTCToken);
        (vaultAddresses.vaultVetoed, vaultAddresses.delegatorVetoed, vaultAddresses.slasherVetoed) =
            deployVault.createVaultVetoed(params, 1 days);
        console2.log("VaultVetoed Collateral: ", Vault(vaultAddresses.vaultVetoed).collateral());
        console2.log("VaultVetoed: ", vaultAddresses.vaultVetoed);
        console2.log("DelegatorVetoed: ", vaultAddresses.delegatorVetoed);
        console2.log("SlasherVetoed: ", vaultAddresses.slasherVetoed);
        console2.log(" ");
        return vaultAddresses;
    }

    function _registerOperatorToNetworkAndVault(
        address _vault
    ) public {
        operatorRegistry.registerOperator();
        operatorNetworkOptInService.optIn(tanssi);
        operatorVaultOptInService.optIn(address(_vault));
    }

    function run(
        address _vaultConfigurator,
        address _operatorRegistry,
        address _networkRegistry,
        address _vaultRegistry,
        address _operatorNetworkOptIn,
        address _operatorVaultOptIn
    ) external {
        vm.startBroadcast(ownerPrivateKey);
        deployCollateral = new DeployCollateral();
        deployVault = new DeployVault();
        vm.stopBroadcast();

        vaultConfigurator = VaultConfigurator(_vaultConfigurator);
        operatorRegistry = OperatorRegistry(_operatorRegistry);
        networkRegistry = NetworkRegistry(_networkRegistry);
        operatorNetworkOptInService = OptInService(_operatorNetworkOptIn);
        operatorVaultOptInService = OptInService(_operatorVaultOptIn);

        deployTokens();
        deployVaults();

        vm.startBroadcast(ownerPrivateKey);
        INetworkRestakeDelegator(vaultAddresses.delegator).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setMaxNetworkLimit(0, 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegator).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);
        INetworkRestakeDelegator(vaultAddresses.delegatorVetoed).setNetworkLimit(tanssi.subnetwork(0), 1000 ether);

        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator2, 300 ether
        );
        IFullRestakeDelegator(vaultAddresses.delegatorVetoed).setOperatorNetworkLimit(
            tanssi.subnetwork(0), operator3, 300 ether
        );
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(tanssi.subnetwork(0), operator, 1);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(tanssi.subnetwork(0), operator2, 1);
        INetworkRestakeDelegator(vaultAddresses.delegator).setOperatorNetworkShares(tanssi.subnetwork(0), operator3, 1);
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator, 1
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator2, 1
        );
        INetworkRestakeDelegator(vaultAddresses.delegatorSlashable).setOperatorNetworkShares(
            tanssi.subnetwork(0), operator3, 1
        );
        middleware = new Middleware(
            tanssi,
            _operatorRegistry,
            _vaultRegistry,
            _operatorNetworkOptIn,
            tanssi,
            NETWORK_EPOCH_DURATION,
            SLASHING_WINDOW
        );
        console2.log("Middleware: ", address(middleware));
        //Already registered during deployment
        // networkRegistry.registerNetwork();
        vm.stopBroadcast();

        vm.startBroadcast(operatorPrivateKey);
        _registerOperatorToNetworkAndVault(vaultAddresses.vault);
        operatorVaultOptInService.optIn(address(vaultAddresses.vaultSlashable));
        vm.stopBroadcast();

        vm.startBroadcast(operator2PrivateKey);
        _registerOperatorToNetworkAndVault(vaultAddresses.vaultSlashable);
        vm.stopBroadcast();

        vm.startBroadcast(operator3PrivateKey);
        _registerOperatorToNetworkAndVault(vaultAddresses.vaultVetoed);
        operatorVaultOptInService.optIn(address(vaultAddresses.vault));
        operatorVaultOptInService.optIn(address(vaultAddresses.vaultSlashable));
        vm.stopBroadcast();

        Vault vault = Vault(vaultAddresses.vault);
        Vault vaultSlashable = Vault(vaultAddresses.vaultSlashable);
        Vault vaultVetoed = Vault(vaultAddresses.vaultVetoed);

        vm.startBroadcast(ownerPrivateKey);
        middleware.registerOperator(operator, abi.encode(OPERATOR_KEY), address(0));
        middleware.registerOperator(operator2, abi.encode(OPERATOR_KEY2), address(0));

        IODefaultStakerRewards.InitParams stakerRewardsParams = IODefaultStakerRewards.InitParams({
            vault: address(0),
            adminFee: 0,
            defaultAdminRoleHolder: tanssi,
            adminFeeClaimRoleHolder: tanssi,
            adminFeeSetRoleHolder: tanssi,
            operatorRewardsRoleHolder: tanssi,
            network: tanssi
        });
        middleware.registerSharedVault(address(vault), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultSlashable), stakerRewardsParams);
        middleware.registerSharedVault(address(vaultVetoed), stakerRewardsParams);
        vm.stopBroadcast();

        vm.startBroadcast(operatorPrivateKey);
        stETHToken.approve(vaultAddresses.vault, 1000 ether);
        vault.deposit{gas: 600_000}(operator, 1000 ether);

        rETHToken.approve(vaultAddresses.vaultSlashable, 1000 ether);
        vaultSlashable.deposit{gas: 600_000}(operator, 1000 ether);
        vm.stopBroadcast();

        vm.startBroadcast(operator2PrivateKey);
        rETHToken.approve(vaultAddresses.vaultSlashable, 1000 ether);
        vaultSlashable.deposit{gas: 600_000}(operator2, 1000 ether);
        vm.stopBroadcast();

        vm.startBroadcast(operator3PrivateKey);
        stETHToken.approve(vaultAddresses.vault, 1000 ether);
        vault.deposit{gas: 600_000}(operator3, 1000 ether);

        rETHToken.approve(vaultAddresses.vaultSlashable, 1000 ether);
        vaultSlashable.deposit{gas: 600_000}(operator3, 1000 ether);

        wBTCToken.approve(vaultAddresses.vaultVetoed, 1000 ether);
        vaultVetoed.deposit{gas: 600_000}(operator3, 1000 ether);
        vm.stopBroadcast();

        vm.startBroadcast(ownerPrivateKey);
        uint48 currentEpoch = middleware.getCurrentEpoch();
        address[] memory activeOperators = middleware.getOperatorsByEpoch(currentEpoch);
        for (uint256 i = 0; i < activeOperators.length; i++) {
            console2.log("Active Operator: ", activeOperators[i]);
        }

        Middleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(currentEpoch);
        for (uint256 i = 0; i < operatorVaultPairs.length; i++) {
            console2.log("Operator: ", operatorVaultPairs[i].operator);
            for (uint256 j = 0; j < operatorVaultPairs[i].vaults.length; j++) {
                console2.log("Vault: ", operatorVaultPairs[i].vaults[j]);
            }
        }

        vm.stopBroadcast();
    }
}
