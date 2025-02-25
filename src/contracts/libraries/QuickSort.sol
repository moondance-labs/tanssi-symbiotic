// SPDX-License-Identifier: MIT

// Copyr---ight (C) Moondance Labs Ltd.
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
pragma solidity ^0.8.0;

import {IMiddleware} from "../../interfaces/middleware/IMiddleware.sol";

/**
 * @title QuickSort library
 * @notice This library is used to sort the validator data array in descending order of stakes
 * @dev This library is used in the middleware to sort the validator data array in descending order of stakes
 */
library QuickSort {
    function quickSort(
        IMiddleware.ValidatorData[] memory arr,
        int256 left,
        int256 right
    ) internal pure returns (IMiddleware.ValidatorData[] memory) {
        _quickSort(arr, left, right);
        return arr;
    }

    function _quickSort(IMiddleware.ValidatorData[] memory arr, int256 left, int256 right) public pure {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].stake;
        while (i <= j) {
            while (arr[uint256(i)].stake > pivot) i++;
            while (pivot > arr[uint256(j)].stake) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (arr[uint256(j)], arr[uint256(i)]);
                i++;
                j--;
            }
        }
        if (left < j) {
            _quickSort(arr, left, j);
        }
        if (i < right) {
            _quickSort(arr, i, right);
        }
    }
}
