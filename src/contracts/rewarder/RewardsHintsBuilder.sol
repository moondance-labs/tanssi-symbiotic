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

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IVaultHints} from "src/interfaces/hints/IVaultHints.sol";

contract RewardsHintsBuilder {
    IOBaseMiddlewareReader public immutable i_middlewareReader;
    IVaultHints public immutable i_vaultHints;

    constructor(address middleware, address vaultHints) {
        i_middlewareReader = IOBaseMiddlewareReader(middleware);
        i_vaultHints = IVaultHints(vaultHints);
    }

    function batchGetHintsForStakerClaimRewards(
        address vault,
        address staker,
        uint48[] calldata epochs
    ) external view returns (bytes[] memory data) {
        uint256 totalEpochs = epochs.length;
        data = new bytes[](totalEpochs);
        for (uint256 i; i < totalEpochs;) {
            uint48 epochStartTs = i_middlewareReader.getEpochStart(epochs[i]);
            data[i] = _getHintsForStakerClaimRewards(vault, staker, epochStartTs);
            unchecked {
                ++i;
            }
        }
    }

    function getHintsForStakerClaimRewards(
        address vault,
        address staker,
        uint48 epoch
    ) external view returns (bytes memory data) {
        uint48 epochStartTs = i_middlewareReader.getEpochStart(epoch);
        data = _getHintsForStakerClaimRewards(vault, staker, epochStartTs);
    }

    function _getHintsForStakerClaimRewards(
        address vault,
        address staker,
        uint48 epochStartTs
    ) private view returns (bytes memory data) {
        data = i_vaultHints.activeSharesOfHint(vault, staker, epochStartTs);
    }
}
