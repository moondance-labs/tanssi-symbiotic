// SPDX-License-Identifier: MIT
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
