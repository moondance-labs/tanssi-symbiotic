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
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IVaultHints} from "src/interfaces/hints/IVaultHints.sol";

contract RewardsHintsBuilder {
    IOBaseMiddlewareReader public immutable i_middlewareReader;
    IODefaultOperatorRewards public immutable i_operatorRewards;
    IVaultHints public immutable i_vaultHints;

    constructor(address middleware, address operatorRewards, address vaultHints) {
        i_middlewareReader = IOBaseMiddlewareReader(middleware);
        i_operatorRewards = IODefaultOperatorRewards(operatorRewards);
        i_vaultHints = IVaultHints(vaultHints);
    }

    function getDataForOperatorClaimRewards(
        bytes32 operatorKey,
        uint48 eraIndex,
        uint256 maxAdminFee
    ) external view returns (bytes memory) {
        address operator = IOBaseMiddlewareReader(i_middlewareReader).operatorByKey(abi.encode(operatorKey));

        IODefaultOperatorRewards.EraRoot memory eraRoot = i_operatorRewards.eraRoot(eraIndex);
        uint48 epochStartTs = i_middlewareReader.getEpochStart(eraRoot.epoch);

        (, address[] memory operatorVaults) =
            IOBaseMiddlewareReader(i_middlewareReader).getOperatorVaults(operator, epochStartTs);

        uint256 totalVaults = operatorVaults.length;
        IODefaultOperatorRewards.VaultHints[] memory hints = new IODefaultOperatorRewards.VaultHints[](totalVaults);
        for (uint256 i; i < totalVaults;) {
            address vault = operatorVaults[i];
            bytes memory activeSharesHint = i_vaultHints.activeSharesHint(vault, epochStartTs);
            bytes memory activeStakeHint = i_vaultHints.activeStakeHint(vault, epochStartTs);

            hints[i] = IODefaultOperatorRewards.VaultHints({
                vault: vault,
                activeSharesHint: activeSharesHint,
                activeStakeHint: activeStakeHint
            });

            unchecked {
                ++i;
            }
        }

        return abi.encode(maxAdminFee, hints);
    }

    function batchGetHintsForStakerClaimRewards(
        address vault,
        address staker,
        uint48[] calldata epochs
    ) external view returns (bytes[] memory data) {
        uint256 totalEpochs = epochs.length;
        data = new bytes[](totalEpochs);
        for (uint256 i; i < totalEpochs;) {
            data[i] = _getHintsForStakerClaimRewards(vault, staker, epochs[i]);
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
        bytes memory activeSharesHint = i_vaultHints.activeSharesOfHint(vault, staker, epochStartTs);
        data = abi.encode(activeSharesHint);
    }
}
