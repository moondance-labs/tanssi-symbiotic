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

    function testUpgradeMiddlewareFailsIfUnexpectedVersion() public {
        address middleware = _deployMiddleware();

        address newOperatorRewardsAddress = makeAddr("newOperatorRewardsAddress");
        address newStakerRewardsFactoryAddress = makeAddr("newStakerRewardsFactoryAddress");
        vm.expectRevert("Middleware version is not expected, cannot upgrade");
        deployTanssiEcosystem.upgradeMiddleware(
            middleware, 2, newOperatorRewardsAddress, newStakerRewardsFactoryAddress, tanssi
        );
    }

    //     function testFullDeployment() public {
    //         vm.startPrank(tanssi);
    //         deployTanssiEcosystem.deployTanssiEcosystem(helperConfig);

    //         // Verify ecosystem entities were deployed
    // (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
    // IVaultConfigurator vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);
    // address middleware = _deployMiddleware();
    //         assertTrue(address(middleware) != address(0));
    //         assertTrue(address(vaultConfigurator) != address(0));

    //         assertEq(OBaseMiddlewareReader(address(middleware)).NETWORK(), tanssi);
    //         assertEq(EpochCapture(address(middleware)).getEpochDuration(), deployTanssiEcosystem.NETWORK_EPOCH_DURATION());
    //         assertEq(OBaseMiddlewareReader(address(middleware)).SLASHING_WINDOW(), deployTanssiEcosystem.SLASHING_WINDOW());
    //         vm.stopPrank();
    //     }

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
            network: address(0)
        });

        vm.expectRevert(DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector);
        deployVault.createBaseVault(params);
    }

    function testDeployVaultRun() public {
        vm.recordLogs();
        (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
        IVaultConfigurator vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);

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
        (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
        IVaultConfigurator vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);

        deployVault.run(address(vaultConfigurator), tanssi, address(1), VAULT_EPOCH_DURATION, false, 0, 1, false, 0, 0);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i = 0; i < entries.length; i++) {
            assertNotEq(
                entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
            );
        }
    }

    // function testDeployVaultWithIndex2() public {
    //     vm.recordLogs();
    //     (address vaultConfiguratorAddress,,,,,,,,) = helperConfig.activeNetworkConfig();
    //     IVaultConfigurator vaultConfigurator = IVaultConfigurator(vaultConfiguratorAddress);
    //     address middleware = _deployMiddleware();

    //     IRegistry operatorRegistry = IRegistry(OBaseMiddlewareReader(address(middleware)).OPERATOR_REGISTRY());
    //     vm.mockCall(
    //         address(operatorRegistry), abi.encodeWithSelector(operatorRegistry.isEntity.selector), abi.encode(true)
    //     );
    //     deployVault.run(address(vaultConfigurator), tanssi, address(1), VAULT_EPOCH_DURATION, false, 0, 2, false, 0, 0);

    //     Vm.Log[] memory entries = vm.getRecordedLogs();
    //     for (uint256 i = 0; i < entries.length; i++) {
    //         assertNotEq(
    //             entries[i].topics[0], DeployVault.DeployVault__VaultConfiguratorOrCollateralNotDeployed.selector
    //         );
    //     }
    // }

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
            delegatorIndex: uint64(0),
            withSlasher: true,
            slasherIndex: 0,
            vetoDuration: 0,
            operator: address(0),
            network: address(0)
        });

        (vault,,) = deployVault.deployVault(deployParams);
    }

    //**************************************************************************************************
    //                                      DEPLOY REWARDS
    //**************************************************************************************************

    function testDeployRewards() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        (address vaultConfigurator,,,,,,,,) = helperConfig.activeNetworkConfig();
        address stETHToken = deployCollateral.deployCollateral("stETH");
        address vault = _deployVault(stETHToken, vaultConfigurator);

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
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);
        assertNotEq(operatorRewards, ZERO_ADDRESS);
    }

    function testUpgradeRewardsOperator() public {
        DeploySymbiotic.SymbioticAddresses memory addresses = deploySymbiotic.deploySymbioticBroadcast();

        address operatorRewards =
            deployRewards.deployOperatorRewardsContract(tanssi, addresses.networkMiddlewareService, 20, tanssi);

        deployRewards.upgradeOperatorRewards(operatorRewards, tanssi, addresses.networkMiddlewareService);
    }

    function testUpgradeRewardsOperatorWithBroadcast() public {
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
