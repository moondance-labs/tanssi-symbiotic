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

import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";

abstract contract MiddlewareStorage {
    /// @custom:storage-location erc7201:tanssi.middleware.MiddlewareStorage.v1.1
    struct StorageMiddleware {
        address gateway;
        uint256 lastTimestamp;
        address forwarderAddress;
        uint256 interval;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.MiddlewareStorage.v1.1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MIDDLEWARE_STORAGE_LOCATION =
        0xca64b196a0d05040904d062f739ed1d1e1d3cc5de78f7001fb9039595fce9100;

    uint256 public constant VERSION = 1;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    bytes32 internal constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    bytes32 internal constant FORWARDER_ROLE = keccak256("FORWARDER_ROLE");

    /**
     * @notice Get the operator rewards contract address
     * @return operator rewards contract address
     */
    address public immutable i_operatorRewards;

    /**
     * @notice Get the staker rewards factory contract address
     * @return staker rewards factory contract address
     */
    address public immutable i_stakerRewardsFactory;

    function _getMiddlewareStorage() internal pure returns (StorageMiddleware storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_LOCATION
        }
    }

    /**
     * @notice Get the gateway contract
     * @return gateway contract
     */
    function getGateway() public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.gateway;
    }

    /**
     * @notice Get the last timestamp
     * @return last timestamp
     */
    function getLastTimestamp() public view returns (uint256) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.lastTimestamp;
    }

    /**
     * @notice Get the forwarder address
     * @return forwarder address
     */
    function getForwarderAddress() public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.forwarderAddress;
    }

    /**
     * @notice Get the interval
     * @return interval
     */
    function getInterval() public view returns (uint256) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.interval;
    }
}
