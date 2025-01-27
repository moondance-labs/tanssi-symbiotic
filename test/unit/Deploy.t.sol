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

import {Test, console2, Vm} from "forge-std/Test.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

import {Token} from "test/mocks/Token.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";

import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract DeployTest is Test {
    using Subnetwork for address;

    address constant ZERO_ADDRESS = address(0);

    DeployCollateral deployCollateral;
    DeploySymbiotic deploySymbiotic;
    DeployTanssiEcosystem deployTanssiEcosystem;
    DeployVault deployVault;
    HelperConfig helperConfig;

    address tanssi;
    address operator;
    address operator2;
    address operator3;

    function setUp() public {
        deployCollateral = new DeployCollateral();
        deploySymbiotic = new DeploySymbiotic();
        deployTanssiEcosystem = new DeployTanssiEcosystem();
        deployVault = new DeployVault();
        helperConfig = new HelperConfig();

        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);
        tanssi = deployTanssiEcosystem.tanssi();
        operator = deployTanssiEcosystem.operator();
        operator2 = deployTanssiEcosystem.operator2();
        operator3 = deployTanssiEcosystem.operator3();
    }

    function testDeployCollateral() public {
        address tokenAddress = deployCollateral.deployCollateral("Test");
        assertNotEq(tokenAddress, ZERO_ADDRESS);
        address tokenAddressBroadcast = deployCollateral.deployCollateralBroadcast("Test");
        assertNotEq(tokenAddressBroadcast, ZERO_ADDRESS);

        deployCollateral.run();
    }

    function testDeploySymbiotic() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        assertNotEq(addresses.vaultFactory, ZERO_ADDRESS);
        assertNotEq(addresses.delegatorFactory, ZERO_ADDRESS);
        assertNotEq(addresses.slasherFactory, ZERO_ADDRESS);
        assertNotEq(addresses.networkRegistry, ZERO_ADDRESS);
        assertNotEq(addresses.operatorRegistry, ZERO_ADDRESS);
        assertNotEq(addresses.operatorMetadataService, ZERO_ADDRESS);
        assertNotEq(addresses.networkMetadataService, ZERO_ADDRESS);
        assertNotEq(addresses.networkMiddlewareService, ZERO_ADDRESS);
        assertNotEq(addresses.operatorVaultOptInService, ZERO_ADDRESS);
        assertNotEq(addresses.operatorNetworkOptInService, ZERO_ADDRESS);
        assertNotEq(addresses.vaultImpl, ZERO_ADDRESS);
        assertNotEq(addresses.vaultTokenizedImpl, ZERO_ADDRESS);
        assertNotEq(addresses.networkRestakeDelegatorImpl, ZERO_ADDRESS);
        assertNotEq(addresses.fullRestakeDelegatorImpl, ZERO_ADDRESS);
        assertNotEq(addresses.operatorSpecificDelegatorImpl, ZERO_ADDRESS);
        assertNotEq(addresses.slasherImpl, ZERO_ADDRESS);
        assertNotEq(addresses.vetoSlasherImpl, ZERO_ADDRESS);
        assertNotEq(addresses.vaultConfigurator, ZERO_ADDRESS);

        vm.recordLogs();
        deployCollateral.run();

        Vm.Log[] memory entries = vm.getRecordedLogs();

        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(entries[i].topics[0], DeploySymbiotic.DeploySymbiotic__VaultsAddresseslNotDeployed.selector);
        }
    }

    function testDeploySymbioticCollateralGetSet() public {
        address tokenAddress = deployCollateral.deployCollateral("Test");
        assertNotEq(tokenAddress, ZERO_ADDRESS);

        address tokenAddressBroadcast = deployCollateral.deployCollateralBroadcast("Test");
        assertNotEq(tokenAddressBroadcast, ZERO_ADDRESS);

        deploySymbiotic.setCollateral(tokenAddress);
        address collateralAddress = deploySymbiotic.getCollateral();
        assertEq(collateralAddress, tokenAddress);
    }

    function testDeployTokens() public {
        vm.startPrank(tanssi);

        (address stETH, address rETH, address wBTC) = deployTanssiEcosystem.deployTokens(tanssi);

        // Verify tokens were deployed
        assertTrue(stETH != address(0));
        assertTrue(rETH != address(0));
        assertTrue(wBTC != address(0));

        // Verify token balances
        Token stETHToken = Token(stETH);
        Token rETHToken = Token(rETH);
        Token wBTCToken = Token(wBTC);

        // Check tanssi balances
        assertEq(stETHToken.balanceOf(tanssi), 8000 ether); // 10000 - 2000 (transferred to operators)
        assertEq(rETHToken.balanceOf(tanssi), 7000 ether); // 10000 - 3000 (transferred to operators)
        assertEq(wBTCToken.balanceOf(tanssi), 9000 ether); // 10000 - 1000 (transferred to operator3)

        // Check operator balances
        assertEq(stETHToken.balanceOf(operator), 1000 ether);
        assertEq(stETHToken.balanceOf(operator3), 1000 ether);

        assertEq(rETHToken.balanceOf(operator), 1000 ether);
        assertEq(rETHToken.balanceOf(operator2), 1000 ether);
        assertEq(rETHToken.balanceOf(operator3), 1000 ether);

        assertEq(wBTCToken.balanceOf(operator3), 1000 ether);
        vm.stopPrank();
    }

    function testDeployVaults() public {
        vm.startPrank(tanssi);
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault != address(0));
        assertTrue(vaultAddresses.delegator != address(0));
        assertTrue(vaultAddresses.slasher != address(0));
        assertTrue(vaultAddresses.vaultSlashable != address(0));
        assertTrue(vaultAddresses.delegatorSlashable != address(0));
        assertTrue(vaultAddresses.slasherSlashable != address(0));
        assertTrue(vaultAddresses.vaultVetoed != address(0));
        assertTrue(vaultAddresses.delegatorVetoed != address(0));
        assertTrue(vaultAddresses.slasherVetoed != address(0));

        // Verify vault configurations
        assertEq(IVault(vaultAddresses.vault).epochDuration(), deployTanssiEcosystem.VAULT_EPOCH_DURATION());
        assertEq(IVault(vaultAddresses.vaultSlashable).epochDuration(), deployTanssiEcosystem.VAULT_EPOCH_DURATION());
        assertEq(IVault(vaultAddresses.vaultVetoed).epochDuration(), deployTanssiEcosystem.VAULT_EPOCH_DURATION());
        vm.stopPrank();
    }

    function testSetDelegatorConfigs() public {
        vm.startPrank(tanssi);
        // Deploy tokens and vaults first
        deployTanssiEcosystem.deployTokens(tanssi);
        deployTanssiEcosystem.deployVaults();

        // Set delegator configs
        deployTanssiEcosystem._setDelegatorConfigs();

        // Get vault addresses
        (, address delegator,,, address delegatorSlashable,,, address delegatorVetoed,) =
            deployTanssiEcosystem.vaultAddresses();

        // Verify network limits
        assertEq(INetworkRestakeDelegator(delegator).maxNetworkLimit(0), deployTanssiEcosystem.MAX_NETWORK_LIMIT());
        assertEq(
            INetworkRestakeDelegator(delegatorSlashable).maxNetworkLimit(0), deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorVetoed).maxNetworkLimit(0), deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );

        // Verify subnet network limits
        assertEq(
            INetworkRestakeDelegator(delegator).networkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorSlashable).networkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorVetoed).networkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        vm.stopPrank();
    }

    function testRegisterEntitiesToMiddleware() public {
        vm.startPrank(tanssi);
        // Deploy full ecosystem
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        (Middleware middleware, IVaultConfigurator vaultConfigurator, address defaultCollateralAddress) =
            deployTanssiEcosystem.ecosystemEntities();
        (address vault,,, address vaultSlashable,,, address vaultVetoed,,) = deployTanssiEcosystem.vaultAddresses();

        // Verify vault registrations
        assertTrue(middleware.isVaultRegistered(vault));
        assertTrue(middleware.isVaultRegistered(vaultSlashable));
        assertTrue(middleware.isVaultRegistered(vaultVetoed));
        vm.stopPrank();
    }

    function testFullDeployment() public {
        vm.startPrank(tanssi);
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        // Verify ecosystem entities were deployed
        (Middleware middleware, IVaultConfigurator vaultConfigurator, address defaultCollateralAddress) =
            deployTanssiEcosystem.ecosystemEntities();
        assertTrue(address(middleware) != address(0));
        assertTrue(address(vaultConfigurator) != address(0));

        assertEq(middleware.i_owner(), tanssi);
        assertEq(middleware.i_epochDuration(), deployTanssiEcosystem.NETWORK_EPOCH_DURATION());
        assertEq(middleware.i_slashingWindow(), deployTanssiEcosystem.SLASHING_WINDOW());
        vm.stopPrank();
    }
}
