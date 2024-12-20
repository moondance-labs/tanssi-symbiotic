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

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {MapWithTimeData} from "src/contracts/libraries/MapWithTimeData.sol";

contract MapWithTimeDataContract {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    EnumerableMap.AddressToUintMap internal elements;

    function add(
        address addr
    ) public {
        elements.add(addr);
    }

    function disable(
        address addr
    ) public {
        elements.disable(addr);
    }

    function enable(
        address addr
    ) public {
        elements.enable(addr);
    }

    function atWithTimes(
        uint256 idx
    ) public view returns (address key, uint48 enabledTime, uint48 disabledTime) {
        return elements.atWithTimes(idx);
    }

    function getTimes(
        address addr
    ) public view returns (uint48 enabledTime, uint48 disabledTime) {
        return elements.getTimes(addr);
    }

    function wasActiveAt(address addr, uint48 timestamp) public view returns (bool) {
        (uint48 enabledTime, uint48 disabledTime) = getTimes(addr);

        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }
}
