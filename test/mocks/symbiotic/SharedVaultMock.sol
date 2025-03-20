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

import {KeyManager256} from "@symbiotic-middleware/extensions/managers/keys/KeyManager256.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {OSharedVaults} from "src/contracts/extensions/OSharedVaults.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

contract SharedVaultMock is OSharedVaults, KeyManager256, EpochCapture {
    function _checkAccess() internal override {}

    function stakeToPower(address, uint256) public pure override returns (uint256 power) {}

    function callBeforeRegisterHook(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) public checkAccess {
        _beforeRegisterSharedVault(sharedVault, stakerRewardsParams);
        _afterRegisterSharedVault(sharedVault);
    }
}
