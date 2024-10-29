// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {Token} from "../test/mocks/Token.sol";

contract DeployCollateral is Script {
    function run() external {
        uint256 deployerPrivateKey =
            vm.envOr("PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        address owner = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        Token token = new Token("Token");
        console2.log("Collateral: ", address(token));
        console2.log("Owner: ", owner);
        console2.log("Balance: ", token.balanceOf(owner));
        vm.stopBroadcast();
    }
}
