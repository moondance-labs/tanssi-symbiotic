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

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {ITanssiMetaMiddleware} from "@tanssi-meta-middleware/interfaces/ITanssiMetaMiddleware.sol";

library MiddlewareStorage {
    /// @custom:storage-location erc7201:tanssi.middleware.MiddlewareStorage.v1.1
    struct StorageMiddleware {
        address _legacyGateway;
        uint256 lastTimestamp;
        uint256 _legacyInterval;
        address _legacyForwarderAddress; // This now lives in the meta middleware
        mapping(address collateral => address oracle) _legacyCollateralToOracle; // This now lives in the meta middleware
        mapping(address vault => address collateral) vaultToCollateral;
        uint256 lastExecutionBlock;
        address i_operatorRewards;
        address i_stakerRewardsFactory;
        ITanssiMetaMiddleware i_metaMiddleware;
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

    uint256 public constant VERSION = 1;
    uint256 public constant MIN_INTERVAL_TO_SEND_OPERATOR_KEYS = 50; // 50 blocks of ~12 seconds each ≈ 600 seconds ≈ 10 minutes
    uint256 public constant MAX_OPERATORS_TO_PROCESS = 10;
    uint256 public constant MAX_OPERATORS_TO_SEND = 58; // This will result in a performData size of 1984 bytes, just below the 2000 bytes limit for the performData: https://docs.chain.link/chainlink-automation/overview/supported-networks
    bytes32 internal constant META_MIDDLEWARE_ROLE = keccak256("META_MIDDLEWARE_ROLE");
    bytes32 internal constant FORWARDER_ROLE = keccak256("FORWARDER_ROLE");
    uint256 public constant MAX_ACTIVE_VAULTS = 80;

    function setVaultToCollateral(
        address vault
    ) external {
        StorageMiddleware storage $ = getMiddlewareStorage();
        address collateral = IVault(vault).collateral();
        if (collateral == address(0)) {
            revert IMiddleware.Middleware__InvalidAddress();
        }
        $.vaultToCollateral[vault] = collateral;
    }

    /**
     * @notice Get the operator rewards contract address
     * @return operator rewards contract address
     */
    function getOperatorRewardsAddress() public view returns (address) {
        StorageMiddleware storage $ = getMiddlewareStorage();
        return $.i_operatorRewards;
    }

    /**
     * @notice Get the staker rewards factory contract address
     * @return staker rewards factory contract address
     */
    function getStakerRewardsFactoryAddress() public view returns (address) {
        StorageMiddleware storage $ = getMiddlewareStorage();
        return $.i_stakerRewardsFactory;
    }

    function getMiddlewareStorage() public pure returns (StorageMiddleware storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_LOCATION
        }
    }

    function getMiddlewareStorageCache() public pure returns (StorageMiddlewareCache storage $v1) {
        assembly {
            $v1.slot := MIDDLEWARE_STORAGE_CACHE_LOCATION
        }
    }

    /**
     * @notice Get the last timestamp
     * @return last timestamp
     */
    function getLastTimestamp() public view returns (uint256) {
        StorageMiddleware storage $ = getMiddlewareStorage();
        return $.lastTimestamp;
    }

    /**
     * @notice Get the meta middleware contract
     * @return meta middleware contract
     */
    function getMetaMiddlewareAddress() public view returns (address) {
        StorageMiddleware storage $ = getMiddlewareStorage();
        return address($.i_metaMiddleware);
    }

    /**
     * @notice Get the collateral address for a vault
     * @return collateral address
     */
    function vaultToCollateral(
        address vault
    ) public view returns (address) {
        StorageMiddleware storage $ = getMiddlewareStorage();
        return $.vaultToCollateral[vault];
    }

    /**
     * @notice Get epoch operators cache index
     * @param epoch The epoch number
     * @return The index of the cache for the epoch or how many operators have had their powers cached
     */
    function getEpochCacheIndex(
        uint48 epoch
    ) public view returns (uint256) {
        StorageMiddlewareCache storage $ = getMiddlewareStorageCache();
        return $.epochToCacheIndex[epoch];
    }

    /**
     * @notice Get the power of an operator
     * @param epoch The epoch number
     * @param operatorKey The operator key
     * @return The power of the operator
     */
    function getOperatorToPowerCached(uint48 epoch, bytes32 operatorKey) public view returns (uint256) {
        StorageMiddlewareCache storage $ = getMiddlewareStorageCache();
        return $.operatorKeyToPower[epoch][operatorKey];
    }
}
