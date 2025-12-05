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
import {MiddlewareProxy} from "src/contracts/middleware/MiddlewareProxy.sol";
import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";
import {OBaseMiddlewareReaderForwarder} from "src/contracts/middleware/OBaseMiddlewareReaderForwarder.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {AggregatorV3DIAProxy} from "src/contracts/oracle-proxy/AggregatorV3DIAProxy.sol";

contract DeployTanssiEcosystem is Script {
    uint256 ownerPrivateKey =
        vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
    address public tanssi = vm.addr(ownerPrivateKey);
    bool public isTest = true;

    function deployMiddlewareWithProxy(
        IMiddleware.InitParams memory params
    ) public returns (Middleware _middleware) {
        Middleware _middlewareImpl = new Middleware();
        _middleware = Middleware(address(new MiddlewareProxy(address(_middlewareImpl), "")));

        if (params.reader == address(0)) {
            params.reader = address(new OBaseMiddlewareReader());
        }
        _middleware.initialize(params);
    }

    function deployMiddleware(
        IMiddleware.InitParams memory params,
        address networkMiddlewareServiceAddress
    ) external returns (address middleware) {
        vm.startBroadcast(broadcaster());

        middleware = address(deployMiddlewareWithProxy(params));

        if (networkMiddlewareServiceAddress != address(0)) {
            INetworkMiddlewareService(networkMiddlewareServiceAddress).setMiddleware(address(middleware));
        }

        vm.stopBroadcast();
    }

    function upgradeMiddlewareBroadcast(address proxyAddress, uint256 expectedCurrentVersion) external {
        isTest = false;
        upgradeMiddleware(proxyAddress, expectedCurrentVersion, address(0));
    }

    function upgradeMiddleware(address proxyAddress, uint256 expectedCurrentVersion, address contractOwner) public {
        if (!isTest) {
            vm.startBroadcast(broadcaster());
        } else {
            vm.startPrank(contractOwner);
        }
        Middleware newImplementation = new Middleware();
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

    function deployOnlyMiddleware(
        bool deployReader
    ) public returns (Middleware newImplementation, OBaseMiddlewareReader reader) {
        vm.startBroadcast(broadcaster());
        newImplementation = new Middleware();
        if (deployReader) {
            reader = new OBaseMiddlewareReader();
            console2.log("Reader: ", address(reader));
        }
        console2.log("New implementation: ", address(newImplementation));

        vm.stopBroadcast();
    }

    function deployMiddlewareReader() public returns (OBaseMiddlewareReader reader) {
        vm.startBroadcast(broadcaster());
        reader = new OBaseMiddlewareReader();
        console2.log("New reader: ", address(reader));

        vm.stopBroadcast();
    }

    function deployMiddlewareReaderForwarder(
        address middleware
    ) public returns (OBaseMiddlewareReaderForwarder reader) {
        vm.startBroadcast(broadcaster());
        reader = new OBaseMiddlewareReaderForwarder(middleware);
        console2.log("New reader forwarder: ", address(reader));

        vm.stopBroadcast();
    }

    function deployDIAAggregatorOracleProxy(
        address diaOracleAddress,
        string calldata pairSymbol
    ) external returns (AggregatorV3DIAProxy aggregatorProxy) {
        vm.startBroadcast(broadcaster());
        if (diaOracleAddress == address(0) || bytes(pairSymbol).length == 0) {
            revert("Invalid DIA Oracle address or pair symbol");
        }
        aggregatorProxy = new AggregatorV3DIAProxy(diaOracleAddress, pairSymbol);
        console2.log("DIA Aggregator Proxy deployed at: ", address(aggregatorProxy));
        vm.stopBroadcast();
    }

    function broadcaster() private view returns (address) {
        if (block.chainid == 1) {
            return msg.sender;
        }
        return vm.addr(ownerPrivateKey);
    }
}
