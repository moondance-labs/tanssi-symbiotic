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

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MiddlewareV3 is UUPSUpgradeable {
    uint256 public constant VERSION = 3;

    address public immutable OPERATORS_REWARDS;

    error MiddlewareV3__UpgradeNotAuthorized();

    constructor(
        address operatorRewardsAddress
    ) {
        _disableInitializers();
        OPERATORS_REWARDS = operatorRewardsAddress;
    }

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal pure override {
        revert MiddlewareV3__UpgradeNotAuthorized();
    }
}
