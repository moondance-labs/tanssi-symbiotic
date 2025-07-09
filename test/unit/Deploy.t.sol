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

import {Test, Vm, console2} from "forge-std/Test.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
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

import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {ODefaultStakerRewards} from "src/contracts/rewarder/ODefaultStakerRewards.sol";
import {Token} from "test/mocks/Token.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {DeployCollateral} from "script/DeployCollateral.s.sol";
import {DeploySymbiotic} from "script/DeploySymbiotic.s.sol";
import {DeployTanssiEcosystem} from "script/DeployTanssiEcosystem.s.sol";
import {DeployVault} from "script/DeployVault.s.sol";
import {DeployRewards} from "script/DeployRewards.s.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {DeployTanssiEcosystemDemo} from "demos/DeployTanssiEcosystemDemo.s.sol";

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

    address operatorRewardsAddress;
    address stakerRewardsFactoryAddress;

    function setUp() public {
        deployCollateral = new DeployCollateral();
        deploySymbiotic = new DeploySymbiotic();
        deployTanssiEcosystem = new DeployTanssiEcosystem();
        deployVault = new DeployVault();
        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        helperConfig = new HelperConfig();
        (, tanssi,,,,,) = helperConfig.activeEntities();

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

    function testDeployMiddleware() public {
        address middleware = _deployMiddleware();
        assertNotEq(middleware, ZERO_ADDRESS);
    }

    function testUpgradeMiddleware() public {
        address middleware = _deployMiddleware();

        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        deployTanssiEcosystem.upgradeMiddleware(
            middleware, 1, newOperatorRewardsAddress, newStakerRewardsFactoryAddress, tanssi
        );
        assertEq(Middleware(middleware).i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(Middleware(middleware).i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
    }

    function testUpgradeMiddlewareWithBroadcast() public {
        address middleware = _deployMiddleware();

        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        deployTanssiEcosystem.upgradeMiddlewareBroadcast(
            middleware, 1, newOperatorRewardsAddress, newStakerRewardsFactoryAddress
        );
        assertEq(Middleware(middleware).i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(Middleware(middleware).i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
    }

    function testDeployOnlyMiddlewareWithReader() public {
        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        (Middleware middleware, OBaseMiddlewareReader reader) =
            deployTanssiEcosystem.deployOnlyMiddleware(newOperatorRewardsAddress, newStakerRewardsFactoryAddress, true);
        assertTrue(address(middleware) != ZERO_ADDRESS);
        assertEq(Middleware(middleware).i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(Middleware(middleware).i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
        assertTrue(address(reader) != ZERO_ADDRESS);
    }

    function testDeployOnlyMiddleware() public {
        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        (Middleware middleware, OBaseMiddlewareReader reader) =
            deployTanssiEcosystem.deployOnlyMiddleware(newOperatorRewardsAddress, newStakerRewardsFactoryAddress, false);
        assertTrue(address(middleware) != ZERO_ADDRESS);
        assertEq(middleware.i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(middleware.i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
        assertEq(address(reader), ZERO_ADDRESS);
    }

    function testDeployOnlyMiddlewareOnMainnet() public {
        vm.chainId(1);
        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        (Middleware middleware, OBaseMiddlewareReader reader) =
            deployTanssiEcosystem.deployOnlyMiddleware(newOperatorRewardsAddress, newStakerRewardsFactoryAddress, false);
        assertTrue(address(middleware) != ZERO_ADDRESS);
        assertEq(middleware.i_operatorRewards(), newOperatorRewardsAddress);
        assertEq(middleware.i_stakerRewardsFactory(), newStakerRewardsFactoryAddress);
        assertEq(address(reader), ZERO_ADDRESS);
    }

    function testUpgradeMiddlewareFailsIfUnexpectedVersion() public {
        address middleware = _deployMiddleware();

        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        vm.expectRevert("Middleware version is not expected, cannot upgrade");
        deployTanssiEcosystem.upgradeMiddleware(
            middleware, 2, newOperatorRewardsAddress, newStakerRewardsFactoryAddress, tanssi
        );
    }

    //**************************************************************************************************
    //                                      DEPLOY VAULT
    //**************************************************************************************************
    function testDeployVaultWithCollateralEmpty() public {
        (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
        IVaultConfigurator vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);

        DeployVault.CreateVaultBaseParams memory params = DeployVault.CreateVaultBaseParams({
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            shouldBroadcast: false,
            vaultConfigurator: address(vaultConfigurator),
            collateral: address(0),
            owner: tanssi,
            operator: address(0),
            network: address(0),
            burner: address(0xDead)
        });

        vm.expectRevert(DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector);
        deployVault.createBaseVault(params);
    }

    function testDeployVaultDirectCall() public {
        vm.recordLogs();

        (address vaultConfigurator,,,,,,,,) = helperConfig.activeNetworkConfig();
        address stETHToken = deployCollateral.deployCollateral("stETH");
        address vault = _deployVault(stETHToken, vaultConfigurator);
        assertNotEq(vault, ZERO_ADDRESS);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    function _deployVault(address token, address vaultConfigurator) private returns (address vault) {
        DeployVault.VaultDeployParams memory deployParams = DeployVault.VaultDeployParams({
            vaultConfigurator: vaultConfigurator,
            owner: tanssi,
            collateral: token,
            epochDuration: VAULT_EPOCH_DURATION,
            depositWhitelist: false,
            depositLimit: 0,
            delegatorIndex: VaultManager.DelegatorType.NETWORK_RESTAKE,
            withSlasher: true,
            slasherIndex: VaultManager.SlasherType.INSTANT,
            vetoDuration: 0,
            operator: address(0),
            network: address(0),
            burner: address(0xDead)
        });

        (vault,,) = deployVault.deployVault(deployParams);
    }

    //**************************************************************************************************
    //                                      DEPLOY REWARDS
    //**************************************************************************************************

    function testDeployOperatorRewards() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);
        assertNotEq(operatorRewards, ZERO_ADDRESS);
    }

    function testDeployOperatorRewardsMainnet() public {
        vm.chainId(1);
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        deployRewards.setIsTest(false);
        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);
        assertNotEq(operatorRewards, ZERO_ADDRESS);
    }

    function testUpgradeOperatorRewards() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);

        deployRewards.upgradeOperatorRewards(operatorRewards, tanssi, addresses.networkMiddlewareService);
    }

    function testUpgradeOperatorRewardsWithBroadcast() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        deployRewards.setIsTest(false);

        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);

        deployRewards.upgradeOperatorRewards(operatorRewards, tanssi, addresses.networkMiddlewareService);
    }

    function testDeployRewardsStakerFactory() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);

        address stakerFactory = deployRewards.deployStakerRewardsFactoryContract(
            addresses.vaultFactory, addresses.networkMiddlewareService, operatorRewards, tanssi
        );
        assertNotEq(stakerFactory, ZERO_ADDRESS);
    }

    function testDemo() public {
        DeployTanssiEcosystemDemo deployTanssiEcosystemDemo = new DeployTanssiEcosystemDemo();
        deployTanssiEcosystemDemo.run();

        vm.warp(block.timestamp + deployTanssiEcosystemDemo.NETWORK_EPOCH_DURATION() * 5 + 1);
        (Middleware middleware,,) = deployTanssiEcosystemDemo.ecosystemEntities();
        uint48 currentEpoch = middleware.getCurrentEpoch();
        assertEq(currentEpoch, 5);

        bytes32[] memory sortedKeys = OBaseMiddlewareReader(address(middleware)).sortOperatorsByPower(currentEpoch);
        assertEq(sortedKeys.length, 3);
    }

    function testDeployTanssiVault() public {
        (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
        address tanssiToken = deployCollateral.deployCollateral("TANSSI");
        deployVault.createTanssiVault(vaultConfiguratorAddress, tanssi, tanssiToken);
    }

    //**************************************************************************************************
    //                                      PRIVATE FUNCTIONS
    //**************************************************************************************************

    function _deployMiddleware() private returns (address) {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();
        address operatorRegistry = addresses.operatorRegistry;
        address vaultFactory = addresses.vaultFactory;
        address operatorNetworkOptIn = addresses.operatorNetworkOptInService;
        address networkMiddlewareService = addresses.networkMiddlewareService;

        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: tanssi,
            operatorRegistry: operatorRegistry,
            vaultRegistry: vaultFactory,
            operatorNetworkOptIn: operatorNetworkOptIn,
            owner: tanssi,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: 8 days,
            reader: address(0)
        });
        address middleware = deployTanssiEcosystem.deployMiddleware(
            params, operatorRewardsAddress, stakerRewardsFactoryAddress, networkMiddlewareService
        );
        return middleware;
    }
}
