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
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {ODefaultOperatorRewards} from "src/contracts/rewarder/ODefaultOperatorRewards.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {DeployRewards} from "./DeployRewards.s.sol";

// Sessions: 1h
// Eras: 6h
// Middleware epochs: 1d
// Slashing window: 2d
// Vault epoch: 7d

contract DeployProduction is Script {
    uint48 public constant NETWORK_EPOCH_DURATION = 1 days;
    uint48 public constant SLASHING_WINDOW = 2 days;
    uint48 public constant OPERATOR_SHARE = 2000;

    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));

    Entities public entities;
    HelperConfig public helperConfig;
    DeployRewards public deployRewards;
    Middleware middleware;
    address initialAdmin;

    struct Entities {
        address admin;
        address tanssi;
        address gateway;
        address forwarder;
    }

    function localDeploy(
        HelperConfig _helperConfig,
        Entities memory _entities,
        address _initialAdmin
    )
        external
        returns (address middlewareAddress, address operatorRewardsAddress, address stakerRewardsFactoryAddress)
    {
        helperConfig = _helperConfig;
        deployRewards = new DeployRewards();
        deployRewards.setIsTest(true);
        entities = _entities;
        initialAdmin = _initialAdmin;

        (middlewareAddress, operatorRewardsAddress, stakerRewardsFactoryAddress) = _deploy(true);
    }

    function deploy()
        external
        returns (address middlewareAddress, address operatorRewardsAddress, address stakerRewardsFactoryAddress)
    {
        helperConfig = new HelperConfig();
        deployRewards = new DeployRewards();
        deployRewards.setIsTest(false);
        _loadEntities();
        initialAdmin = vm.addr(ownerPrivateKey);

        (middlewareAddress, operatorRewardsAddress, stakerRewardsFactoryAddress) = _deploy(false);
    }

    function _deploy(
        bool isTest
    )
        private
        returns (address middlewareAddress, address operatorRewardsAddress, address stakerRewardsFactoryAddress)
    {
        (
            ,
            address operatorRegistryAddress,
            ,
            address vaultRegistryAddress,
            address operatorNetworkOptInServiceAddress,
            ,
            address networkMiddlewareServiceAddress,
            ,
        ) = helperConfig.activeNetworkConfig();

        // Deploy rewards takes care of starting and ending broadcast
        operatorRewardsAddress = deployRewards.deployOperatorRewardsContract(
            entities.tanssi, networkMiddlewareServiceAddress, OPERATOR_SHARE, initialAdmin
        );
        stakerRewardsFactoryAddress = deployRewards.deployStakerRewardsFactoryContract(
            vaultRegistryAddress, networkMiddlewareServiceAddress, operatorRewardsAddress, entities.tanssi, initialAdmin
        );

        if (isTest) {
            vm.startPrank(initialAdmin);
        } else {
            vm.startBroadcast(ownerPrivateKey); // This is also the initial admin when running on production
        }

        address reader = address(new OBaseMiddlewareReader());
        IMiddleware.InitParams memory params = IMiddleware.InitParams({
            network: entities.tanssi,
            operatorRegistry: operatorRegistryAddress,
            vaultRegistry: vaultRegistryAddress,
            operatorNetworkOptIn: operatorNetworkOptInServiceAddress,
            owner: initialAdmin,
            epochDuration: NETWORK_EPOCH_DURATION,
            slashingWindow: SLASHING_WINDOW,
            reader: reader
        });

        Middleware middlewareImpl = new Middleware();
        middlewareAddress = address(new MiddlewareProxy(address(middlewareImpl), ""));
        middleware = Middleware(middlewareAddress);
        middleware.initialize(params);

        // All these needs to be called by the admin, we could make ourselves admins initially to do so:
        // middleware.setForwarder(entities.forwarder); // Not needed initially
        // middleware.setGateway(entities.gateway); // Not needed initially
        middleware.grantRole(middleware.DEFAULT_ADMIN_ROLE(), entities.admin);

        ODefaultOperatorRewards operatorRewards = ODefaultOperatorRewards(operatorRewardsAddress);
        operatorRewards.grantRole(operatorRewards.MIDDLEWARE_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.STAKER_REWARDS_SETTER_ROLE(), address(middleware));
        operatorRewards.grantRole(operatorRewards.DEFAULT_ADMIN_ROLE(), entities.admin);

        if (isTest) {
            vm.stopPrank();
        } else {
            vm.stopBroadcast();
        }

        // TODO: Initial admin needs to renounce its admin role once real admin is tested

        // This needs to be called as the network, must be done from multisig:
        // if (!INetworkRegistry(networkRegistryAddress).isEntity(entities.tanssi)) {
        //     INetworkRegistry(networkRegistryAddress).registerNetwork();
        // }

        // This needs to be called as the network, must be done from multisig:
        // INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(address(middleware));

        if (!isTest) {
            console2.log("Tanssi (Safe): ", entities.tanssi);
            console2.log("Admin (Safe): ", entities.admin);
            console2.log("Initial Admin: ", initialAdmin);
            console2.log("Gateway: ", entities.gateway);
            console2.log("Forwarder: ", entities.forwarder);
            console2.log("Middleware: ", address(middleware));
            console2.log("Middleware Implementation: ", address(middlewareImpl));
            console2.log("Reader: ", address(reader));
            console2.log("OperatorRewards: ", operatorRewardsAddress);
            console2.log("StakerRewardsFactory: ", stakerRewardsFactoryAddress);
        }
    }

    function _loadEntities() private {
        (address admin, address tanssi, address gateway, address forwarder,,,) = helperConfig.activeEntities();

        entities = Entities({admin: admin, tanssi: tanssi, gateway: gateway, forwarder: forwarder});
    }
}
