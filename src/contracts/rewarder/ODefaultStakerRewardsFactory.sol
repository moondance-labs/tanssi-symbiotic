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

import {console2} from "forge-std/console2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Registry} from "@symbiotic/contracts/common/Registry.sol";

import {ODefaultStakerRewards} from "./ODefaultStakerRewards.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";

contract ODefaultStakerRewardsFactory is Ownable2Step, Registry, IODefaultStakerRewardsFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    address private _implementation;

    address private immutable i_vaultFactory;
    address private immutable i_networkMiddlewareService;
    address private immutable i_operatorRewards;
    address private immutable i_network;

    constructor(
        address vaultFactory,
        address networkMiddlewareService,
        address operatorRewards,
        address network,
        address owner_
    ) Ownable(owner_) {
        if (
            vaultFactory == address(0) || networkMiddlewareService == address(0) || operatorRewards == address(0)
                || network == address(0)
        ) {
            revert ODefaultStakerRewardsFactory__InvalidAddress();
        }

        i_vaultFactory = vaultFactory;
        i_networkMiddlewareService = networkMiddlewareService;
        i_operatorRewards = operatorRewards;
        i_network = network;
    }

    /**
     * @inheritdoc IODefaultStakerRewardsFactory
     */
    function getImplementation() external view returns (address) {
        return _implementation;
    }

    /**
     * @inheritdoc IODefaultStakerRewardsFactory
     */
    function setImplementation(
        address implementation
    ) external onlyOwner {
        if (implementation == address(0)) {
            revert ODefaultStakerRewardsFactory__InvalidAddress();
        }

        if (implementation == _implementation) {
            revert ODefaultStakerRewardsFactory__AlreadySet();
        }

        _implementation = implementation;
        emit SetImplementation(implementation);
    }

    /**
     * @inheritdoc IODefaultStakerRewardsFactory
     */
    function create(address vault, ODefaultStakerRewards.InitParams calldata params) external returns (address) {
        if (vault == address(0) || !Registry(i_vaultFactory).isEntity(vault)) {
            revert ODefaultStakerRewardsFactory__NotVault();
        }

        if (_implementation != params.implementation) {
            revert ODefaultStakerRewardsFactory__InvalidImplementation();
        }

        address proxy = address(new ERC1967Proxy(_implementation, ""));
        ODefaultStakerRewards(proxy).initialize(i_operatorRewards, vault, params);
        _addEntity(proxy);

        return proxy;
    }
}
