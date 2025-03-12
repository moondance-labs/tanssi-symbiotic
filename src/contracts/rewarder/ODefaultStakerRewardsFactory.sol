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

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Registry} from "@symbioticfi/core/src/contracts/common/Registry.sol";

import {ODefaultStakerRewards} from "./ODefaultStakerRewards.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";

contract ODefaultStakerRewardsFactory is Registry, IODefaultStakerRewardsFactory {
    address private immutable VAULT_FACTORY;
    address private immutable NETWORK_MIDDLEWARE_SERVICE;
    uint48 private immutable START_TIME;
    uint48 private immutable EPOCH_DURATION;

    constructor(address vaultFactory, address networkMiddlewareService, uint48 startTime, uint48 epochDuration) {
        VAULT_FACTORY = vaultFactory;
        NETWORK_MIDDLEWARE_SERVICE = networkMiddlewareService;
        START_TIME = startTime;
        EPOCH_DURATION = epochDuration;
    }

    /**
     * @inheritdoc IODefaultStakerRewardsFactory
     */
    function create(
        ODefaultStakerRewards.InitParams calldata params
    ) external returns (address) {
        ODefaultStakerRewards stakerRewards =
            new ODefaultStakerRewards(VAULT_FACTORY, NETWORK_MIDDLEWARE_SERVICE, START_TIME, EPOCH_DURATION);

        address proxy = address(new ERC1967Proxy((address(stakerRewards)), ""));
        ODefaultStakerRewards(proxy).initialize(params);
        _addEntity(proxy);

        return proxy;
    }
}
