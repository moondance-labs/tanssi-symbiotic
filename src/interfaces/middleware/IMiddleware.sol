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

interface IMiddleware {
    /**
     * @notice Emitted when an oracle is set for a collateral.
     * @dev If the oracle is set to address(0), the collateral will no longer be supported.
     * @param collateral The collateral address
     * @param oracle The oracle address
     */
    event CollateralToOracleSet(address indexed collateral, address indexed oracle);

    /**
     * @notice Emitted when the interval for which the `performUpkeep` should be performed is set.
     * @param interval The interval in seconds
     */
    event IntervalSet(uint256 indexed interval);

    /**
     * @notice Emitted when the forwarder is set.
     * @param forwarder The forwarder address
     */
    event ForwarderSet(address indexed forwarder);

    /**
     * @notice Emitted when a new gateway address is set.
     * @param gateway The new gateway address
     */
    event GatewaySet(address indexed gateway);

    // Errors
    error Middleware__GatewayNotSet();
    error Middleware__AlreadySet();
    error Middleware__InvalidEpoch();
    error Middleware__InvalidEpochDuration();
    error Middleware__InvalidAddress();
    error Middleware__InvalidKey();
    error Middleware__InvalidInterval();
    error Middleware__InsufficientBalance();
    error Middleware__NotSupportedCollateral(address collateral);
    error Middleware__SlashingWindowTooShort();
    error Middleware__OperatorNotFound(bytes32 operatorKey, uint48 epoch);
    error Middleware__SlashPercentageTooBig(uint48 epoch, address operator, uint256 percentage);

    /**
     * @notice Validator data structure containing stake and key
     * @param power The validator's power, based on staked tokens and their price
     * @param key The validator's key
     */
    struct ValidatorData {
        uint256 power;
        bytes32 key;
    }

    /**
     * @notice Structure to store slashing parameters
     * @param epochStartTs The epoch start timestamp
     * @param vault The vault address
     * @param operator The operator address
     * @param slashAmount The amount to slash
     */
    struct SlashParams {
        uint48 epochStartTs;
        address vault;
        address operator;
        uint256 slashPercentage;
    }

    /**
     * @notice Structure to pair an operator with their associated vaults
     * @param operator The operator's address
     * @param vaults Array of vault addresses associated with the operator
     */
    struct OperatorVaultPair {
        address operator;
        address[] vaults;
    }

    /**
     * @param network The network address
     * @param operatorRegistry The operator registry address
     * @param vaultRegistry The vault registry address
     * @param operatorNetOptin The operator network optin address
     * @param owner The owner address
     * @param epochDuration The epoch duration
     * @param slashingWindow The slashing window
     * @param reader The reader address
     */
    struct InitParams {
        address network;
        address operatorRegistry;
        address vaultRegistry;
        address operatorNetworkOptIn;
        address owner;
        uint48 epochDuration;
        uint48 slashingWindow;
        address reader;
    }

    /**
     * @notice Sets the gateway contract
     * @dev Only the owner can call this function
     * @param gateway The gateway contract address
     */
    function setGateway(
        address gateway
    ) external;

    /**
     * @notice Sets the interval on which to let Chainlink forwarder to call `performUpkeep`
     * @dev Only the owner can call this function
     * @param interval The interval
     */
    function setInterval(
        uint256 interval
    ) external;

    /**
     * @notice Sets the forwarder address
     * @param forwarder The forwarder address
     */
    function setForwarder(
        address forwarder
    ) external;

    /**
     * @notice Sets the operator share on operator rewards contract
     * @param operatorShare The operator share
     */
    function setOperatorShareOnOperatorRewards(
        uint48 operatorShare
    ) external;

    /**
     * @notice Distribute rewards for a specific era contained in an epoch by providing a Merkle root, total points, total amount of tokens and the token address of the rewards.
     * @param epoch network epoch of the middleware
     * @param eraIndex era index of Starlight's rewards distribution
     * @param totalPoints total amount of points for the reward distribution
     * @param tokenAmount amount of tokens to distribute
     * @param rewardsRoot Merkle root of the reward distribution
     * @param tokenAddress The token address of the rewards
     * @dev This function is called by the gateway only
     * @dev Emit DistributeRewards event.
     */
    function distributeRewards(
        uint256 epoch,
        uint256 eraIndex,
        uint256 totalPoints,
        uint256 tokenAmount,
        bytes32 rewardsRoot,
        address tokenAddress
    ) external;

    /**
     * @notice Gets the operators' keys for latest epoch
     * @return keys Array of operator keys
     */
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory keys);

    /**
     * @notice Slashes an operator's stake
     * @dev Only the owner can call this function
     * @dev This function first updates the stake cache for the target epoch
     * @param epoch The epoch number
     * @param operatorKey The operator key to slash
     * @param percentage Percentage to slash, represented as parts per billion.
     */
    function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external;
}
