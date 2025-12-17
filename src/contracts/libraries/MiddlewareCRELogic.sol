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
pragma solidity ^0.8.0;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {MiddlewareStorage} from "src/contracts/middleware/MiddlewareStorage.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IOGateway} from "@snowbridge/contracts/src/interfaces/IOGateway.sol";

library MiddlewareCRELogic {
    using Math for uint256;

    error Middleware__NoPerformData();
    error Middleware__GatewayNotSet();
    error Middleware__InvalidEpoch();
    error Middleware__InvalidCommand(uint8 command);
    error Middleware__AlreadyCached();

    uint8 public constant CACHE_DATA_COMMAND = 1;
    uint8 public constant SEND_DATA_COMMAND = 2;
    uint8 public constant CRE_CACHE_DATA_COMMAND = 101;

    function cacheAndSendOperatorsFlow(
        bytes calldata performData,
        uint48 currentEpoch,
        uint256 operatorsLength
    ) external {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        MiddlewareStorage.StorageMiddlewareCache storage cache = MiddlewareStorage.getMiddlewareStorageCache();

        if (performData.length == 0) {
            revert Middleware__NoPerformData();
        }

        uint48 encodedEpoch;
        // Get out from the bytes of the encoded report the epochData.
        assembly {
            // Load 32 bytes starting at offset 32 (second 32-byte slot)
            let epochData := calldataload(add(performData.offset, 32))
            encodedEpoch := epochData
        }

        if (encodedEpoch != currentEpoch) {
            revert Middleware__InvalidEpoch();
        }

        uint256 cacheIndex = cache.epochToCacheIndex[currentEpoch];
        uint256 pendingOperatorsToCache = operatorsLength - cacheIndex;

        if (pendingOperatorsToCache > 0) {
            (uint8 command,, IMiddleware.ValidatorData[] memory validatorsData) =
                abi.decode(performData, (uint8, uint48, IMiddleware.ValidatorData[]));

            if (command != CACHE_DATA_COMMAND) {
                revert Middleware__InvalidCommand(command);
            }

            uint256 validatorsDataLength = validatorsData.length;
            for (uint256 i = 0; i < validatorsDataLength;) {
                IMiddleware.ValidatorData memory validatorData = validatorsData[i];
                bytes32 validatorKey = validatorData.key;

                if (cache.operatorKeyToPower[currentEpoch][validatorKey] != 0) {
                    revert Middleware__AlreadyCached();
                }

                cache.operatorKeyToPower[currentEpoch][validatorKey] = validatorData.power;
                unchecked {
                    ++i;
                }
            }

            unchecked {
                cache.epochToCacheIndex[currentEpoch] += validatorsDataLength;
            }
        } else {
            address gateway = $.gateway;
            if (gateway == address(0)) {
                revert Middleware__GatewayNotSet();
            }

            uint48 currentTimestamp = Time.timestamp();
            if ((currentTimestamp - $.lastTimestamp) > $.interval) {
                $.lastTimestamp = currentTimestamp;

                (uint8 command,, bytes32[] memory sortedKeys) = abi.decode(performData, (uint8, uint48, bytes32[]));

                if (command != SEND_DATA_COMMAND) {
                    revert Middleware__InvalidCommand(command);
                }

                IOGateway(gateway).sendOperatorsData(sortedKeys, currentEpoch);
            }
        }
    }
}
