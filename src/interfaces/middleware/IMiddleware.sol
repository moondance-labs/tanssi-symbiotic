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
    // Events
    /**
     * @notice Emitted when rewards contracts are set
     * @param operatorRewardsAddress Address of the operator rewards contract
     */
    event OperatorRewardContractSet(address indexed operatorRewardsAddress);

    // Errors
    error Middleware__NotOperator();
    error Middleware__NotVault();
    error Middleware__CallerNotGateway();
    error Middleware__GatewayNotSet();
    error Middleware__OperatorRewardsNotSet();
    error Middleware__OperatorNotOptedIn();
    error Middleware__OperatorNotRegistred();
    error Middleware__OperatorGracePeriodNotPassed();
    error Middleware__OperatorAlreadyRegistred();
    error Middleware__VaultAlreadyRegistered();
    error Middleware__VaultEpochTooShort();
    error Middleware__VaultGracePeriodNotPassed();
    error Middleware__InvalidSubnetworksCnt();
    error Middleware__TooOldEpoch();
    error Middleware__InvalidEpoch();
    error Middleware__InvalidAddress();
    error Middleware__InsufficientBalance();
    error Middleware__SlashingWindowTooShort();
    error Middleware__UnknownSlasherType();
    error Middleware__OperatorNotFound(bytes32 operatorKey, uint48 epoch);
    error Middleware__SlashPercentageTooBig(uint48 epoch, address operator, uint256 percentage);

    /**
     * @notice Validator data structure containing stake and key
     * @param stake The validator's stake amount
     * @param key The validator's key
     */
    struct ValidatorData {
        uint256 stake;
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
     * @notice Sets the gateway contract
     * @dev Only the owner can call this function
     * @param _gateway The gateway contract address
     */
    function setGateway(
        address _gateway
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
     * @param totalPointsToken total amount of points for the reward distribution
     * @param tokensInflatedToken amount of tokens to distribute
     * @param rewardsRoot Merkle root of the reward distribution
     * @param tokenAddress The token address of the rewards
     * @dev This function is called by the gateway only
     * @dev Emit DistributeRewards event.
     */
    function distributeRewards(
        uint256 epoch,
        uint256 eraIndex,
        uint256 totalPointsToken,
        uint256 tokensInflatedToken,
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

    // **************************************************************************************************
    //                                      VIEW FUNCTIONS
    // **************************************************************************************************

    /**
     * @notice Gets how many operators were active at a specific epoch
     * @param epoch The epoch at which to check how many operators were active
     * @return activeOperators The array of active operators
     */
    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory activeOperators);

    /**
     * @notice Gets operator-vault pairs for an epoch
     * @param epoch The epoch number
     * @return operatorVaultPairs Array of operator-vault pairs
     */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (OperatorVaultPair[] memory operatorVaultPairs);

    /**
     * @notice Checks if a vault is registered
     * @param vault The vault address to check
     * @return bool True if vault is registered
     */
    function isVaultRegistered(
        address vault
    ) external view returns (bool);

    /**
     * @dev Sorts operators by their total stake in descending order, after 500 it will be almost impossible to be used on-chain since 500 ≈ 36M gas
     * @param epoch The epoch number
     * @return sortedKeys Array of sorted operators keys based on their stake
     */
    function sortOperatorsByVaults(
        uint48 epoch
    ) external view returns (bytes32[] memory sortedKeys);

    /**
     * @notice Gets operator-vault pairs for an operator
     * @param operator the operator address
     * @param epochStartTs the epoch start timestamp
     * @return vaultIdx the index of the vault
     * @return _vaults the array of vaults
     */
    function getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) external view returns (uint256 vaultIdx, address[] memory _vaults);

    /**
     * @notice Gets total stake for an epoch
     * @param epoch The epoch number
     * @return Total stake amount
     */
    function getTotalStake(
        uint48 epoch
    ) external view returns (uint256);

    /**
     * @notice Gets an operator's active key at the current capture timestamp
     * @param operator The operator address to lookup
     * @return The operator's active key encoded as bytes, or encoded zero bytes if none
     */
    function getOperatorKeyAt(address operator, uint48 timestamp) external view returns (bytes memory);

    /**
     * @notice Gets validator set for an epoch
     * @param epoch The epoch number
     * @return validatorsData Array of validator data
     */
    function getValidatorSet(
        uint48 epoch
    ) external view returns (ValidatorData[] memory validatorsData);

    /**
     * @notice Determines which epoch a timestamp belongs to
     * @param timestamp The timestamp to check
     * @return epoch The corresponding epoch number
     */
    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48 epoch);
}
