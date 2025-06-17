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

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IOperatorRegistry} from "@symbiotic/interfaces/IOperatorRegistry.sol";
import {INetworkRegistry} from "@symbiotic/interfaces/INetworkRegistry.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IDefaultCollateralFactory} from
    "@symbiotic-collateral/interfaces/defaultCollateral/IDefaultCollateralFactory.sol";
import {DefaultCollateralFactory} from "@symbiotic-collateral/contracts/defaultCollateral/DefaultCollateralFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";

import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {Token} from "test/mocks/Token.sol";
import {DeployCollateral} from "./DeployCollateral.s.sol";
import {DeployVault} from "./DeployVault.s.sol";
import {DeployRewards} from "./DeployRewards.s.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract DeployTanssiEcosystem is Script {
    using Subnetwork for address;

    uint48 public constant VAULT_EPOCH_DURATION = 12 days;
    uint48 public constant NETWORK_EPOCH_DURATION = 6 days;
    uint48 public constant SLASHING_WINDOW = 7 days;
    uint48 public constant OPERATOR_NETWORK_SHARES = 1;
    uint128 public constant MAX_NETWORK_LIMIT = 1000 ether;
    uint128 public constant OPERATOR_NETWORK_LIMIT = 300 ether;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public tanssi = vm.addr(ownerPrivateKey);
    bool public isTest = true;

    function deployMiddlewareWithProxy(
        IMiddleware.InitParams memory params,
        address operatorRewards,
        address stakerRewardsFactory
    ) public returns (Middleware _middleware) {
        Middleware _middlewareImpl = new Middleware(operatorRewards, stakerRewardsFactory);
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));

        if (params.reader == address(0)) {
            params.reader = address(new OBaseMiddlewareReader());
        }
        _middleware.initialize(params);
    }

    function deployMiddleware(
        IMiddleware.InitParams memory params,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress,
        address networkMiddlewareServiceAddress
    ) external returns (address middleware) {
        vm.startBroadcast(ownerPrivateKey);

        middleware = address(deployMiddlewareWithProxy(params, operatorRewardsAddress, stakerRewardsFactoryAddress));

        if (networkMiddlewareServiceAddress != address(0)) {
            INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(address(middleware));
        }

        vm.stopBroadcast();
    }

    function upgradeMiddlewareBroadcast(
        address proxyAddress,
        uint256 expectedCurrentVersion,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress
    ) external {
        isTest = false;
        upgradeMiddleware(
            proxyAddress, expectedCurrentVersion, operatorRewardsAddress, stakerRewardsFactoryAddress, address(0)
        );
    }

    function upgradeMiddleware(
        address proxyAddress,
        uint256 expectedCurrentVersion,
        address operatorRewardsAddress,
        address stakerRewardsFactoryAddress,
        address contractOwner
    ) public {
        if (!isTest) {
            vm.startBroadcast(ownerPrivateKey);
        } else {
            vm.startPrank(contractOwner);
        }
        Middleware newImplementation = new Middleware(operatorRewardsAddress, stakerRewardsFactoryAddress);
        Middleware proxy = Middleware(proxyAddress);
        uint256 currentVersion = proxy.VERSION();
        if (currentVersion != expectedCurrentVersion) {
            revert("Middleware version is not expected, cannot upgrade");
        }
        proxy.upgradeToAndCall(address(newImplementation), hex"");
        console2.log("New implementation: ", address(newImplementation));
        if (!isTest) {
            vm.stopBroadcast();
        } else {
            vm.stopPrank();
        }
    }
}
