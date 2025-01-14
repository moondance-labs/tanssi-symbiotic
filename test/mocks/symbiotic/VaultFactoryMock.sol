// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract VaultFactoryMock {
    error EntityNotExist();

    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _entities;

    function addEntity(
        address entity_
    ) external {
        _entities.add(entity_);
    }

    function isEntity(
        address entity_
    ) public view returns (bool) {
        return _entities.contains(entity_);
    }

    function totalEntities() public view returns (uint256) {
        return _entities.length();
    }

    function entity(
        uint256 index
    ) public view returns (address) {
        return _entities.at(index);
    }

    function _checkEntity(
        address account
    ) internal view {
        if (!isEntity(account)) {
            revert EntityNotExist();
        }
    }
}
