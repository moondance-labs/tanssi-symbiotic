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
    uint256 public constant VERSION = 1;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    bytes32 internal constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.MiddlewareStorage.v1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MIDDLEWARE_STORAGE_LOCATION =
        0x744f79b1118793e0a060dca4f01184704394f6e567161215b3d2c3126631e700;

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

    /// @custom:storage-location erc7201:tanssi.middleware.MiddlewareStorage.v1
    struct StorageMiddleware {
        address gateway;
        //Unused, can be removed on fresh/prod deployment
        mapping(uint48 epoch => uint256 amount) totalStakeCache;
        mapping(uint48 epoch => bool) totalStakeIsCached;
        mapping(uint48 epoch => mapping(address operator => uint256 amount)) operatorStakeCache;
    }

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
}
