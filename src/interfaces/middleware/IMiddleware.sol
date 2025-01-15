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

interface IMiddleware {
    // Events
    /**
     * @notice Emitted when rewards contracts are set
     * @param stakerRewardsAddress Address of the staker rewards contract
     * @param operatorRewardsAddress Address of the operator rewards contract
     */
    event RewardsContractsSet(address indexed stakerRewardsAddress, address indexed operatorRewardsAddress);

    /**
     * @notice Emitted when an invalid timeframe for slashing is detected
     * @param epoch the epoch number
     * @param operator the address of the operator
     * @param amount the amount to slash
     */
    event InvalidSlashTimeframe(uint48 indexed epoch, address indexed operator, uint256 indexed amount);

    // Errors
    error Middleware__NotOperator();
    error Middleware__NotVault();
    error Middleware__OperatorNotOptedIn();
    error Middleware__OperatorNotRegistred();
    error Middleware__OperarorGracePeriodNotPassed();
    error Middleware__OperatorAlreadyRegistred();
    error Middleware__VaultAlreadyRegistered();
    error Middleware__VaultEpochTooShort();
    error Middleware__VaultGracePeriodNotPassed();
    error Middleware__InvalidSubnetworksCnt();
    error Middleware__TooOldEpoch();
    error Middleware__InvalidEpoch();
    error Middleware__SlashingWindowTooShort();
    error Middleware__TooBigSlashAmount();
    error Middleware__UnknownSlasherType();

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
     * @param totalOperatorStake The total operator stake
     * @param slashAmount The amount to slash
     */
    struct SlashParams {
        uint48 epochStartTs;
        address vault;
        address operator;
        uint256 totalOperatorStake;
        uint256 slashAmount;
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
     * @notice Get the network subnetwork count
     * @return amount of subnetworks in the network
     */
    function s_subnetworksCount() external view returns (uint256 amount);

    /**
     * @notice Get the cached total stake amount for an epoch
     * @param epoch epoch of which to get the total stake
     * @return amount total stake amount
     */
    function s_totalStakeCache(
        uint48 epoch
    ) external view returns (uint256 amount);

    /**
     * @notice Get the total stake cache status for an epoch
     * @param epoch epoch of which to get the cache status
     * @return true if the total stake is cached, false otherwise
     */
    function s_totalStakeCached(
        uint48 epoch
    ) external view returns (bool);

    /**
     * @notice Get the operator's stake amount cached for an epoch
     * @param epoch epoch of the related operator's stake
     * @param operator operator's address
     * @return operator's stake amount
     */
    function s_operatorStakeCache(uint48 epoch, address operator) external view returns (uint256);

    /**
     * @notice Registers a new operator with a key
     * @param operator The operator's address
     * @param key The operator's key
     */
    function registerOperator(address operator, bytes32 key) external;

    /**
     * @notice Updates an existing operator's key
     * @param operator The operator's address
     * @param key The new key
     */
    function updateOperatorKey(address operator, bytes32 key) external;

    /**
     * @notice Pauses an operator
     * @param operator The operator to pause
     */
    function pauseOperator(
        address operator
    ) external;

    /**
     * @notice Re-enables a paused operator
     * @param operator The operator to unpause
     */
    function unpauseOperator(
        address operator
    ) external;

    /**
     * @notice Removes an operator after grace period
     * @param operator The operator to unregister
     */
    function unregisterOperator(
        address operator
    ) external;

    /**
     * @notice Registers a new vault
     * @param vault The vault address to register
     */
    function registerVault(
        address vault
    ) external;

    /**
     * @notice Pauses a vault
     * @param vault The vault to pause
     */
    function pauseVault(
        address vault
    ) external;

    /**
     * @notice Re-enables a paused vault
     * @param vault The vault to unpause
     */
    function unpauseVault(
        address vault
    ) external;

    /**
     * @notice Removes a vault after grace period
     * @param vault The vault to unregister
     */
    function unregisterVault(
        address vault
    ) external;

    /**
     * @notice Updates the number of subnetworks
     * @param _subnetworksCount New subnetwork count
     */
    function setSubnetworksCount(
        uint256 _subnetworksCount
    ) external;

    /**
     * @notice Sets the gateway contract
     * @param _gateway The gateway contract address
     */
    function setGateway(
        address _gateway
    ) external;

    /**
     * @notice Sets the rewards contracts
     * @param stakerRewardsAddress Address of the staker rewards contract
     * @param operatorRewardsAddress Address of the operator rewards contract
     */
    function setRewardsContracts(address stakerRewardsAddress, address operatorRewardsAddress) external;

    /**
     * @notice Distributes rewards
     * @param data Additional data for distribution
     */
    function distributeRewards(
        bytes calldata data
    ) external;

    /**
     * @notice Calculates and caches stakes for an epoch
     * @param epoch The epoch to calculate for
     * @return Total stake amount
     */
    function calcAndCacheStakes(
        uint48 epoch
    ) external returns (uint256);

    /**
     * @notice Slashes an operator's stake
     * @param epoch The epoch number
     * @param operator The operator to slash
     * @param amount Amount to slash
     */
    function slash(uint48 epoch, address operator, uint256 amount) external;

    /**
     * @notice Gets how many operators were active at a specific epoch
     * @param epoch The epoch at which to check how many operators were active
     * @return Array of active operators
     */
    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory);

    /**
     * @notice Gets the operators' keys for latest epoch
     * @return Array of operator keys
     */
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory);

    /**
     * @notice Gets operator-vault pairs for an epoch
     * @param epoch The epoch number
     * @return Array of operator-vault pairs
     */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (OperatorVaultPair[] memory);

    /**
     * @notice Checks if a vault is registered
     * @param vault The vault address to check
     * @return True if vault is registered
     */
    function isVaultRegistered(
        address vault
    ) external view returns (bool);

    /**
     * @notice Gets operator's stake for an epoch
     * @param operator The operator address
     * @param epoch The epoch number
     * @return The operator's stake
     */
    function getOperatorStake(address operator, uint48 epoch) external view returns (uint256);

    /**
     * @notice Gets total stake for an epoch
     * @param epoch The epoch number
     * @return Total stake amount
     */
    function getTotalStake(
        uint48 epoch
    ) external view returns (uint256);

    /**
     * @notice Gets validator set for an epoch
     * @param epoch The epoch number
     * @return Array of validator data
     */
    function getValidatorSet(
        uint48 epoch
    ) external view returns (ValidatorData[] memory);

    /**
     * @notice Gets the timestamp when an epoch starts
     * @param epoch The epoch number
     * @return The start time of the epoch
     */
    function getEpochStartTs(
        uint48 epoch
    ) external view returns (uint48);

    /**
     * @notice Determines which epoch a timestamp belongs to
     * @param timestamp The timestamp to check
     * @return The corresponding epoch number
     */
    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48);

    /**
     * @notice Gets the current epoch number
     * @return The current epoch
     */
    function getCurrentEpoch() external view returns (uint48);
}
