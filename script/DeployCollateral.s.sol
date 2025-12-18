// SPDX-License-Identifier: GPL-3.0-or-later
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

import {Token} from "../test/mocks/Token.sol";

contract DeployCollateral is Script {
    function deployCollateral(
        string memory tokenName
    ) public returns (address) {
        Token token = new Token(tokenName, 18);

        return address(token);
    }

    function deployCollateral(string memory tokenName, uint8 decimals) public returns (address) {
        Token token = new Token(tokenName, decimals);

        return address(token);
    }

    function deployCollateralBroadcast(
        string memory tokenName
    ) public returns (address) {
        uint256 ownerPrivateKey =
            vm.envOr("OWNER_PRIVATE_KEY", uint256(0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6));
        address owner = vm.addr(ownerPrivateKey);

        vm.startBroadcast(ownerPrivateKey);
        address tokenAddress = deployCollateral(tokenName);

        vm.stopBroadcast();

        Token token = Token(tokenAddress);
        console2.log("Collateral: ", address(token));
        console2.log("Owner: ", owner);
        console2.log("Balance: ", token.balanceOf(owner));

        return tokenAddress;
    }
}
