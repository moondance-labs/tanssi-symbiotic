// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {Token} from "../test/mocks/Token.sol";

contract DeployCollateral is Script {
    uint256 public constant OPERATOR_INITIAL_BALANCE = 1000 ether;

    function run() external {
        deployCollateralBroadcast();
    }

    function deployCollateral() public returns (address) {
        Token token = new Token("Token");

        return address(token);
    }

    function deployCollateralBroadcast() public {
        uint256 ownerPrivateKey =
            vm.envOr("OWNER_PRIVATE_KEY", uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80));
        address owner = vm.addr(ownerPrivateKey);

        vm.startBroadcast(ownerPrivateKey);
        address tokenAddress = deployCollateral();

        vm.stopBroadcast();

        Token token = Token(tokenAddress);
        console2.log("Collateral: ", address(token));
        console2.log("Owner: ", owner);
        console2.log("Balance: ", token.balanceOf(owner));
    }
}
