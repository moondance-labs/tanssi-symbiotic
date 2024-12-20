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
// along with Tanssi.  If not, see <http://www.gnu.org/licenses/>MIT
pragma solidity ^0.8.25;

import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

library MapWithTimeData {
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    error AlreadyAdded();
    error NotEnabled();
    error AlreadyEnabled();

    uint256 private constant ENABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant DISABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF << 48;

    function add(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        if (!self.set(addr, uint256(0))) {
            revert AlreadyAdded();
        }
    }

    function disable(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        uint256 value = self.get(addr);

        if (uint48(value) == 0 || uint48(value >> 48) != 0) {
            revert NotEnabled();
        }

        value |= uint256(Time.timestamp()) << 48;
        self.set(addr, value);
    }

    function enable(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        uint256 value = self.get(addr);

        if (uint48(value) != 0 && uint48(value >> 48) == 0) {
            revert AlreadyEnabled();
        }

        value = uint256(Time.timestamp());
        self.set(addr, value);
    }

    function atWithTimes(
        EnumerableMap.AddressToUintMap storage self,
        uint256 idx
    ) internal view returns (address key, uint48 enabledTime, uint48 disabledTime) {
        uint256 value;
        (key, value) = self.at(idx);
        enabledTime = uint48(value);
        disabledTime = uint48(value >> 48);
    }

    function getTimes(
        EnumerableMap.AddressToUintMap storage self,
        address addr
    ) internal view returns (uint48 enabledTime, uint48 disabledTime) {
        uint256 value = self.get(addr);
        enabledTime = uint48(value);
        disabledTime = uint48(value >> 48);
    }
}
