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

import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";

abstract contract MiddlewareStorage {
    /// @custom:storage-location erc7201:tanssi.middleware.MiddlewareStorage.v1.1
    struct StorageMiddleware {
        address gateway;
        uint256 lastTimestamp;
        uint256 interval;
        address forwarderAddress;
        mapping(address collateral => address oracle) collateralToOracle;
        mapping(address vault => address collateral) vaultToCollateral;
        uint256 lastExecutionBlock;
        address i_operatorRewards;
        address i_stakerRewardsFactory;
    }

    struct StorageMiddlewareCache {
        mapping(uint48 epoch => uint256 cacheIndex) epochToCacheIndex;
        mapping(uint48 epoch => mapping(bytes32 operatorKey => uint256 operatorPower)) operatorKeyToPower;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.MiddlewareStorage.v1.1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MIDDLEWARE_STORAGE_LOCATION =
        0xca64b196a0d05040904d062f739ed1d1e1d3cc5de78f7001fb9039595fce9100;

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.MiddlewareStorageCache.v1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant MIDDLEWARE_STORAGE_CACHE_LOCATION =
        0x93540b1a1dc30969947272428a8d0331ac0b23f753e3edd38c70f80cf0835100;

    uint8 public constant DEFAULT_DECIMALS = 18;
    uint8 public constant CACHE_DATA_COMMAND = 1;
    uint8 public constant SEND_DATA_COMMAND = 2;
    uint256 public constant VERSION = 1;
    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;
    uint256 public constant MIN_INTERVAL_TO_SEND_OPERATOR_KEYS = 50; // 50 blocks of ~12 seconds each ≈ 600 seconds ≈ 10 minutes
    uint256 public constant MAX_OPERATORS_TO_PROCESS = 20;
    uint256 public constant MAX_OPERATORS_TO_SEND = 59; // This will result in a performData size of 1984 bytes, just below the 2000 bytes limit for the performData: https://docs.chain.link/chainlink-automation/overview/supported-networks
    bytes32 internal constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
    bytes32 internal constant FORWARDER_ROLE = keccak256("FORWARDER_ROLE");
    uint256 public constant MAX_ACTIVE_VAULTS = 80;

    /**
     * @notice Get the operator rewards contract address
     * @return operator rewards contract address
     */
    function getOperatorRewardsAddress() public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.i_operatorRewards;
    }

    /**
     * @notice Get the staker rewards factory contract address
     * @return staker rewards factory contract address
     */
    function getStakerRewardsFactoryAddress() public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.i_stakerRewardsFactory;
    }

    function _getMiddlewareStorage() internal pure returns (StorageMiddleware storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_LOCATION
        }
    }

    function _getMiddlewareStorageCache() internal pure returns (StorageMiddlewareCache storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_CACHE_LOCATION
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

    /**
     * @notice Get the oracle address for a collateral
     * @return oracle address
     */
    function collateralToOracle(
        address collateral
    ) public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.collateralToOracle[collateral];
    }

    /**
     * @notice Get the collateral address for a vault
     * @return collateral address
     */
    function vaultToCollateral(
        address vault
    ) public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.vaultToCollateral[vault];
    }

    /**
     * @notice Get the oracle address for a vault
     * @return oracle address
     */
    function vaultToOracle(
        address vault
    ) public view returns (address) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        return $.collateralToOracle[$.vaultToCollateral[vault]];
    }

    /**
     * @notice Get epoch operators cache index
     * @param epoch The epoch number
     * @return The index of the cache for the epoch or how many operators have had their powers cached
     */
    function getEpochCacheIndex(
        uint48 epoch
    ) public view returns (uint256) {
        StorageMiddlewareCache storage $ = _getMiddlewareStorageCache();
        return $.epochToCacheIndex[epoch];
    }

    /**
     * @notice Get the power of an operator
     * @param epoch The epoch number
     * @param operatorKey The operator key
     * @return The power of the operator
     */
    function getOperatorToPower(uint48 epoch, bytes32 operatorKey) public view returns (uint256) {
        StorageMiddlewareCache storage $ = _getMiddlewareStorageCache();
        return $.operatorKeyToPower[epoch][operatorKey];
    }
}
