// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {Token} from "../test/mocks/Token.sol";

contract DeployCollateral is Script {
    function run() external {
        vm.startBroadcast();

        Token token = new Token("Token");
        console2.log("Token address: ", address(token));

        vm.stopBroadcast();
    }
}
