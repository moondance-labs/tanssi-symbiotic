// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Registry} from "@symbiotic/contracts/common/Registry.sol";
import {Entity} from "@symbiotic/contracts/common/Entity.sol";

contract RegistryMock is Registry {
    function register() external {
        _addEntity(msg.sender);
    }
}
