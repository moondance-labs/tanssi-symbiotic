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

import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {Script} from "forge-std/Script.sol";
import {MiddlewareStorage} from "src/contracts/middleware/MiddlewareStorage.sol";

contract TestUtils is Script {
    uint8 public constant EXECUTION_CODE_CACHE = 101;

    function getTotalBatchesForCount(
        Middleware middleware,
        uint256 count
    ) public pure returns (uint256) {
        uint256 max = MiddlewareStorage.MAX_OPERATORS_TO_PROCESS;
        uint256 totalBatches = count / max;
        if (totalBatches * max < count) {
            totalBatches++;
        }
        return totalBatches;
    }

    function encodeStringToBytes10(
        string memory stringData
    ) public pure returns (bytes10 encodedString) {
        if (bytes(stringData).length == 0) {
            encodedString = bytes10(0);
            return encodedString;
        }

        // Convert workflow name to bytes10:
        // SHA256 hash → hex encode → take first 10 chars → hex encode those chars
        bytes32 hashData = sha256(bytes(stringData));
        bytes memory hexString = _bytesToHexString(abi.encodePacked(hashData));
        bytes memory first10 = new bytes(10);
        for (uint256 i = 0; i < 10; i++) {
            first10[i] = hexString[i];
        }
        encodedString = bytes10(first10);
    }

    /// @notice Helper function to convert bytes to hex string
    /// @param data The bytes to convert
    /// @return The hex string representation
    function _bytesToHexString(
        bytes memory data
    ) private pure returns (bytes memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory hexString = new bytes(data.length * 2);

        for (uint256 i = 0; i < data.length; i++) {
            hexString[i * 2] = hexChars[uint8(data[i] >> 4)];
            hexString[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }

        return hexString;
    }

    function encodePerformDataToReport(
        uint8 executionCode,
        bytes memory performData
    ) public pure returns (bytes memory report) {
        report = abi.encode(executionCode, performData);
    }
}
