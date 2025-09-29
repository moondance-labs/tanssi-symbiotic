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

import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";

interface IMiddlewareStorage {
    /**
     * @notice Get the gateway contract
     * @return gateway contract
     */
    function getGateway() external view returns (address);

    /**
     * @notice Get the last timestamp
     * @return last timestamp
     */
    function getLastTimestamp() external view returns (uint256);

    /**
     * @notice Get the forwarder address
     * @return forwarder address
     */
    function getForwarderAddress() external view returns (address);

    /**
     * @notice Get the interval
     * @return interval
     */
    function getInterval() external view returns (uint256);

    /**
     * @notice Get the oracle address for a collateral
     * @return oracle address
     */
    function collateralToOracle(
        address collateral
    ) external view returns (address);

    /**
     * @notice Get the collateral address for a vault
     * @return collateral address
     */
    function vaultToCollateral(
        address vault
    ) external view returns (address);

    /**
     * @notice Get the oracle address for a vault
     * @return oracle address
     */
    function vaultToOracle(
        address vault
    ) external view returns (address);

    /**
     * @notice Get epoch operators cache index
     * @param epoch The epoch number
     * @return The index of the cache for the epoch or how many operators have had their powers cached
     */
    function getEpochCacheIndex(
        uint48 epoch
    ) external view returns (uint256);

    /**
     * @notice Get the power of an operator
     * @param epoch The epoch number
     * @param operatorKey The operator key
     * @return The power of the operator
     */
    function getOperatorToPowerCached(uint48 epoch, bytes32 operatorKey) external view returns (uint256);

    /**
     * @notice Get the total power of a vault
     * @param epoch The epoch number
     * @param vault The vault address
     * @return The total power of the vault
     */
    function getVaultToPowerCached(uint48 epoch, address vault) external view returns (uint256);

    /**
     * @notice Get next expected cache command for an epoch
     * @param epoch The epoch number
     * @return The next expected cache command for the epoch
     */
    function getEpochNextExpectedCacheCommand(
        uint48 epoch
    ) external view returns (IMiddleware.CachingState);

    /**
     * @notice Get total power cached for an epoch
     * @param epoch The epoch number
     * @return The total power cached for the epoch
     */
    function getEpochTotalPower(
        uint48 epoch
    ) external view returns (uint256);
}
