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

import {Test, Vm} from "forge-std/Test.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultStorage} from "@symbiotic/interfaces/vault/IVaultStorage.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";

import {IDefaultCollateralFactory} from
    "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateralFactory.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {BaseMiddlewareReader} from "@symbiotic-middleware/middleware/BaseMiddlewareReader.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";

import {Token} from "test/mocks/Token.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";

import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";

contract DeployTest is Test {
    using Subnetwork for address;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 7 days;
    address constant ZERO_ADDRESS = address(0);
    string constant HOLESKY_RPC = "https://ethereum-holesky-rpc.publicnode.com";
    DeployCollateral deployCollateral;
    DeploySymbiotic deploySymbiotic;
    DeployTanssiEcosystem deployTanssiEcosystem;
    DeployVault deployVault;
    DeployRewards deployRewards;
    HelperConfig helperConfig;

    address tanssi;
    address operator;
    address operator2;
    address operator3;

    address operatorRewardsAddress;
    address stakerRewardsFactoryAddress;

    function setUp() public {
        deployCollateral = new DeployCollateral();
        deploySymbiotic = new DeploySymbiotic();
        deployTanssiEcosystem = new DeployTanssiEcosystem();
        deployVault = new DeployVault();
        deployRewards = new DeployRewards();
        helperConfig = new HelperConfig();

        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);
        tanssi = deployTanssiEcosystem.tanssi();
        operator = deployTanssiEcosystem.operator();
        operator2 = deployTanssiEcosystem.operator2();
        operator3 = deployTanssiEcosystem.operator3();

        operatorRewardsAddress = makeAddr("operatorRewards");
        stakerRewardsFactoryAddress = makeAddr("stakerRewardsFactory");
    }

    function _setIsTest() public {
        // isTest is in slot 20 with offset 20
        bytes32 slot = bytes32(uint256(20));

        bytes32 mask = bytes32(uint256(1)) << 160; // Shift 1 to bool's position which is at the 20th byte
        bytes32 clearedValue = (vm.load(address(deployTanssiEcosystem), slot) & ~mask); //Load the current value which should be the operator address and mask it to clear the bool
        vm.store(address(deployTanssiEcosystem), slot, clearedValue);
    }

    //**************************************************************************************************
    //                                      DEPLOY COLLATERAL
    //**************************************************************************************************
    function testDeployCollateral() public {
        address tokenAddress = deployCollateral.deployCollateral("Test");
        assertNotEq(tokenAddress, ZERO_ADDRESS);
        address tokenAddressBroadcast = deployCollateral.deployCollateralBroadcast("Test");
        assertNotEq(tokenAddressBroadcast, ZERO_ADDRESS);

        deployCollateral.run();
    }

    //**************************************************************************************************
    //                                      DEPLOY SYMBIOTIC
    //**************************************************************************************************
    function testDeploySymbioticBroadcast() public {
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

    function testDeploySymbiotic() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploy(tanssi);
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
    }

    function testDeploySymbioticRun() public {
        vm.recordLogs();
        address _collateral = deployCollateral.deployCollateral("Test");
        deploySymbiotic.setCollateral(_collateral);
        deploySymbiotic.run(_collateral);

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

    //**************************************************************************************************
    //                                      DEPLOY TANSSI ECOSYSTEM
    //**************************************************************************************************
    function testDeployTokens() public {
        vm.startPrank(tanssi);

        (Token stETHToken, Token rETHToken, Token wBTCToken) = deployTanssiEcosystem.tokensAddresses();

        // Verify tokens were deployed
        assertTrue(address(stETHToken) != address(0));
        assertTrue(address(rETHToken) != address(0));
        assertTrue(address(wBTCToken) != address(0));

        // Check tanssi balances
        assertEq(stETHToken.balanceOf(tanssi), 8000 ether);
        assertEq(rETHToken.balanceOf(tanssi), 7000 ether);
        assertEq(wBTCToken.balanceOf(tanssi), 9000 ether);

        vm.stopPrank();
    }

    function testDeployMiddleware() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        address operatorRegistry = addresses.operatorRegistry;
        address vaultFactory = addresses.vaultFactory;
        address operatorNetworkOptIn = addresses.operatorNetworkOptInService;

        address middleware = deployTanssiEcosystem.deployMiddleware(
            tanssi,
            operatorRegistry,
            vaultFactory,
            operatorNetworkOptIn,
            tanssi,
            NETWORK_EPOCH_DURATION,
            8 days,
            operatorRewardsAddress,
            stakerRewardsFactoryAddress,
            address(0)
        );
        assertNotEq(middleware, ZERO_ADDRESS);
    }

    function testDeployRegisterVault() public {
        (address _vault,,,,,,,,) = deployTanssiEcosystem.vaultAddresses();

        (Middleware middleware,,) = deployTanssiEcosystem.ecosystemEntities();

        vm.startPrank(tanssi);
        middleware.pauseSharedVault(_vault);
        vm.warp(NETWORK_EPOCH_DURATION + 1);
        middleware.unregisterSharedVault(_vault);
        vm.stopPrank();

        vm.warp(block.timestamp + NETWORK_EPOCH_DURATION + 1);
        deployTanssiEcosystem.registerSharedVault(address(middleware), _vault);
    }

    function testDeployRegisterMiddlewareToSymbiotic() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        address operatorRegistry = addresses.operatorRegistry;
        address vaultFactory = addresses.vaultFactory;
        address operatorNetworkOptIn = addresses.operatorNetworkOptInService;
        address networkMiddlewareService = addresses.networkMiddlewareService;
        uint256 ownerPrivateKey =
            vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
        address _tanssi = vm.addr(ownerPrivateKey);

        address middleware = deployTanssiEcosystem.deployMiddleware(
            _tanssi,
            operatorRegistry,
            vaultFactory,
            operatorNetworkOptIn,
            _tanssi,
            NETWORK_EPOCH_DURATION,
            9 days,
            operatorRewardsAddress,
            stakerRewardsFactoryAddress,
            address(0)
        );

        vm.expectEmit(true, true, false, false);
        emit INetworkMiddlewareService.SetMiddleware(_tanssi, middleware);
        deployTanssiEcosystem.registerMiddlewareToSymbiotic(networkMiddlewareService);
    }

    function testDeployVaultsIsTestYes() public {
        vm.startPrank(tanssi);
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault != address(0));
        assertTrue(vaultAddresses.delegator != address(0));
        assertTrue(vaultAddresses.slasher == address(0));
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

    function testDeployVaultsIsTestNone() public {
        deployTanssiEcosystem.run();
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        vm.startBroadcast(); //To not fail the isBroadcast inside deployVaults
        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault != address(0));
        assertTrue(vaultAddresses.delegator != address(0));
        assertTrue(vaultAddresses.slasher == address(0));
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

    function testDeployVaultsWithChainIdLocal() public {
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        vm.startBroadcast(); //To not fail the isBroadcast inside deployVaults
        vm.chainId(31_337);
        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault != address(0));
        assertTrue(vaultAddresses.delegator != address(0));
        assertTrue(vaultAddresses.slasher == address(0));
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

    function testDeployVaultsWithChainIdSepolia() public {
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        vm.startBroadcast(); //To not fail the isBroadcast inside deployVaults
        vm.chainId(11_155_111);
        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault != address(0));
        assertTrue(vaultAddresses.delegator != address(0));
        assertTrue(vaultAddresses.slasher == address(0));
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

    function testDeployVaultsWithSingleVault() public {
        for (uint256 i = 0; i < 9; i++) {
            vm.store(
                address(deployTanssiEcosystem), // contract address
                bytes32(uint256(21) + i), // slot 21 + offset for each address
                bytes32(0) // zero address
            );
            // Verify the slot is cleared
            bytes32 storedValue = vm.load(address(deployTanssiEcosystem), bytes32(uint256(21) + i));
            require(storedValue == bytes32(0), "Slot not cleared");
        }

        _setIsTest();

        vm.chainId(17_000);
        // First deploy tokens as they're needed for vaults
        deployTanssiEcosystem.deployTokens(tanssi);

        vm.startBroadcast(); //To not fail the isBroadcast inside deployVaults
        // Deploy vaults
        DeployTanssiEcosystem.VaultAddresses memory vaultAddresses = deployTanssiEcosystem.deployVaults();

        // Verify vault addresses
        assertTrue(vaultAddresses.vault == address(0));
        assertTrue(vaultAddresses.delegator == address(0));
        assertTrue(vaultAddresses.slasher == address(0));
        assertTrue(vaultAddresses.vaultSlashable != address(0));
        assertTrue(vaultAddresses.delegatorSlashable != address(0));
        assertTrue(vaultAddresses.slasherSlashable != address(0));
        assertTrue(vaultAddresses.vaultVetoed == address(0));
        assertTrue(vaultAddresses.delegatorVetoed == address(0));
        assertTrue(vaultAddresses.slasherVetoed == address(0));
    }

    function testSetDelegatorConfigs() public {
        vm.startPrank(tanssi);

        // Get vault addresses
        (, address delegator,,, address delegatorSlashable,,, address delegatorVetoed,) =
            deployTanssiEcosystem.vaultAddresses();

        // Verify network limits
        assertEq(
            INetworkRestakeDelegator(delegator).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorSlashable).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorVetoed).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
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

    function testSetDelegatorConfigsWithNonTestnetChain() public {
        vm.createSelectFork(HOLESKY_RPC);

        helperConfig = new HelperConfig();

        deployTanssiEcosystem = new DeployTanssiEcosystem();
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);
        vm.startPrank(tanssi);

        (, address delegator,,, address delegatorSlashable,,, address delegatorVetoed,) =
            deployTanssiEcosystem.vaultAddresses();

        assertEq(
            INetworkRestakeDelegator(delegator).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorSlashable).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorVetoed).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
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

    function testSetDelegatorConfigsWithSepoliaChain() public {
        vm.chainId(11_155_111);
        helperConfig = new HelperConfig();

        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);
        vm.startPrank(tanssi);

        (, address delegator,,, address delegatorSlashable,,, address delegatorVetoed,) =
            deployTanssiEcosystem.vaultAddresses();

        assertEq(
            INetworkRestakeDelegator(delegator).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorSlashable).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
        );
        assertEq(
            INetworkRestakeDelegator(delegatorVetoed).maxNetworkLimit(tanssi.subnetwork(0)),
            deployTanssiEcosystem.MAX_NETWORK_LIMIT()
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

    function testDefaultCollateralBeingDeployedIfHolesky() public {
        vm.createSelectFork(HOLESKY_RPC);

        helperConfig = new HelperConfig();

        deployTanssiEcosystem = new DeployTanssiEcosystem();
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        (,, address defaultCollateralAddress) = deployTanssiEcosystem.ecosystemEntities();

        // Verify default collateral was deployed
        assertTrue(defaultCollateralAddress != address(0));
    }

    function testDefaultCollateralNotBeingDeployedIfLocal() public {
        vm.chainId(31_337);
        vm.startPrank(tanssi);
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        (,, address defaultCollateralAddress) = deployTanssiEcosystem.ecosystemEntities();

        // Verify default collateral was deployed
        assertTrue(defaultCollateralAddress == address(0));
        vm.stopPrank();
    }

    function testDefaultCollateralNotBeingDeployedIfSepolia() public {
        vm.chainId(11_155_111);
        vm.startPrank(tanssi);
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        (,, address defaultCollateralAddress) = deployTanssiEcosystem.ecosystemEntities();

        // Verify default collateral was deployed
        assertTrue(defaultCollateralAddress == address(0));
        vm.stopPrank();
    }

    function testRegisterEntitiesToMiddleware() public {
        vm.startPrank(tanssi);
        // Deploy full ecosystem
        deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

        (Middleware middleware,,) = deployTanssiEcosystem.ecosystemEntities();
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
        (Middleware middleware, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();
        assertTrue(address(middleware) != address(0));
        assertTrue(address(vaultConfigurator) != address(0));

        assertEq(BaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
        assertEq(EpochCapture(address(middleware)).getEpochDuration(), deployTanssiEcosystem.NETWORK_EPOCH_DURATION());
        assertEq(BaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), deployTanssiEcosystem.SLASHING_WINDOW());
        vm.stopPrank();
    }

    function testDeployVaultWithVaultConfiguratorEmpty() public {
        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeployVault.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(0),
            collateral: address(1),
            owner: tanssi
        });

        vm.expectRevert(DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector);
        deployVault.createBaseVault(params);
    }

    //**************************************************************************************************
    //                                      DEPLOY VAULT
    //**************************************************************************************************
    function testDeployVaultWithCollateralEmpty() public {
        (, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();

        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: DeployVault.DelegatorIndex.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(0),
            owner: tanssi
        });

        vm.expectRevert(DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector);
        deployVault.createBaseVault(params);
    }

    function testDeployVaultRun() public {
        vm.recordLogs();
        (, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();

        deployVault.run(address(vaultConfigurator), tanssi, address(1), VAULT_EPOCH_DURATION, false, 0, 0, false, 0, 0);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    function testDeployVaultWithIndex1() public {
        vm.recordLogs();
        (, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();

        deployVault.run(address(vaultConfigurator), tanssi, address(1), VAULT_EPOCH_DURATION, false, 0, 1, false, 0, 0);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    function testDeployVaultWithIndex2() public {
        vm.recordLogs();
        (Middleware middleware, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();

        IRegistry operatorRegistry = IRegistry(BaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY());
        vm.mockCall(
            address(operatorRegistry), abi.encodeWithSelector(operatorRegistry.isEntity.selector), abi.encode(true)
        );
        deployVault.run(address(vaultConfigurator), tanssi, address(1), VAULT_EPOCH_DURATION, false, 0, 2, false, 0, 0);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    function testDeployVaultDirectCall() public {
        vm.recordLogs();

        (, IVaultConfigurator vaultConfigurator,) = deployTanssiEcosystem.ecosystemEntities();

        DeployVault.VaultDeployParams memory deployParams = DeployVault.VaultDeployParams({
            vaultConfigurator: address(vaultConfigurator),
            owner: tanssi,
            collateral: address(1),
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: uint64(0),
            withSlasher: true,
            slasherIndex: 0,
            vetoDuration: 0
        });

        deployVault.deployVault(deployParams);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    //**************************************************************************************************
    //                                      DEPLOY REWARDS
    //**************************************************************************************************

    function testDeployRewards() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        (address vault,,,,,,,,) = deployTanssiEcosystem.vaultAddresses();

        DeployRewards.DeployParams memory params = DeployRewards.DeployParams({
            vault: vault,
            vaultFactory: addresses.vaultFactory,
            adminFee: 0,
            defaultAdminRole: tanssi,
            adminFeeClaimRole: tanssi,
            adminFeeSetRole: tanssi,
            network: tanssi,
            networkMiddlewareService: addresses.networkMiddlewareService,
            startTime: 1 days,
            epochDuration: NETWORK_EPOCH_DURATION,
            operatorShare: 20
        });

        vm.mockCall(addresses.vaultFactory, abi.encodeWithSelector(IRegistry.isEntity.selector), abi.encode(true));

        vm.expectEmit(true, false, false, false);
        emit DeployRewards.Done();
        deployRewards.run(params);
    }

    function testDeployRewardsOperator() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20);
        assertNotEq(operatorRewards, ZERO_ADDRESS);
    }

    function testDeployRewardsStakerFactory() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        (address stakerFactory, address stakerImpl) = deployRewards.deployStakerRewardsFactoryContract(
            addresses.vaultFactory, addresses.networkMiddlewareService, uint48(block.timestamp), NETWORK_EPOCH_DURATION
        );
        assertNotEq(stakerFactory, ZERO_ADDRESS);
        assertNotEq(stakerImpl, ZERO_ADDRESS);
    }

    function testDeployRewardsStaker() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        (address vault,,,,,,,,) = deployTanssiEcosystem.vaultAddresses();

        deployRewards.deployStakerRewardsFactoryContract(
            addresses.vaultFactory, addresses.networkMiddlewareService, 1 days, NETWORK_EPOCH_DURATION
        );
        vm.mockCall(addresses.vaultFactory, abi.encodeWithSelector(IRegistry.isEntity.selector), abi.encode(true));

        address stakerRewards =
            deployRewards.deployStakerRewardsContract(vault, 0, tanssi, tanssi, tanssi, tanssi, tanssi);
        assertNotEq(stakerRewards, ZERO_ADDRESS);
    }
}
