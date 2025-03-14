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

    /**
     * @notice Emitted when an oracle is set for a collateral.
     * @dev If the oracle is set to address(0), the collateral will no longer be supported.
     * @param collateral The collateral address
     * @param oracle The oracle address
     */
    event CollateralToOracleSet(address indexed collateral, address indexed oracle);

    // Errors
    error Middleware__AlreadySet();
    error Middleware__CallerNotGateway();
    error Middleware__GatewayNotSet();
    error Middleware__InsufficientBalance();
    error Middleware__InvalidAddress();
    error Middleware__InvalidEpoch();
    error Middleware__InvalidSubnetworksCnt();
    error Middleware__NotOperator();
    error Middleware__NotSupportedCollateral(address collateral);
    error Middleware__NotVault();
    error Middleware__OperatorAlreadyRegistred();
    error Middleware__OperatorGracePeriodNotPassed();
    error Middleware__OperatorNotFound(bytes32 operatorKey, uint48 epoch);
    error Middleware__OperatorNotOptedIn();
    error Middleware__OperatorNotRegistred();
    error Middleware__OperatorRewardsNotSet();
    error Middleware__SlashingWindowTooShort();
    error Middleware__SlashPercentageTooBig(uint48 epoch, address operator, uint256 percentage);
    error Middleware__TooOldEpoch();
    error Middleware__UnknownSlasherType();
    error Middleware__VaultAlreadyRegistered();
    error Middleware__VaultEpochTooShort();
    error Middleware__VaultGracePeriodNotPassed();

    // /**
    //  * @notice Slasher type enum
    //  * @param INSTANT Instant slasher type
    //  * @param VETO Veto slasher type
    //  */
    // enum SlasherType {
    //     INSTANT,
    //     VETO
    // }

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

    // /**
    //  * @notice Get the network epoch duration
    //  * @return epoch duration
    //  */
    // function i_epochDuration() external view returns (uint48);

    // /**
    //  * @notice Get the network slashing window
    //  * @return slashing window
    //  */
    // function i_slashingWindow() external view returns (uint48);

    // /**
    //  * @notice Get the network start time
    //  * @return start time
    //  */
    // function i_startTime() external view returns (uint48);

    // /**
    //  * @notice Get the network address
    //  * @return network address
    //  */
    // function _NETWORK() external view returns (address);

    // /**
    //  * @notice Get the operator registry address
    //  * @return operator registry address
    //  */
    // function i_operatorRegistry() external view returns (address);

    // /**
    //  * @notice Get the vault registry address
    //  * @return vault registry address
    //  */
    // function i_vaultRegistry() external view returns (address);

    // /**
    //  * @notice Get the operator network optin address
    //  * @return operator network optin address
    //  */
    // function i_operatorNetworkOptin() external view returns (address);

    // /**
    //  * @notice Get the owner address
    //  * @return owner address
    //  */
    // function i_owner() external view returns (address);

    // /**
    //  * @notice Get the network subnetwork count
    //  * @return amount of subnetworks in the network
    //  */
    // function s_subnetworksCount() external view returns (uint256 amount);

    // /**
    //  * @notice Get the operator rewards contract address
    //  * @return operator rewards contract address
    //  */
    // function s_operatorRewards() external view returns (address);

    // /**
    //  * @notice Get the cached total stake amount for an epoch
    //  * @param epoch epoch of which to get the total stake
    //  * @return amount total stake amount
    //  */
    // function s_totalStakeCache(
    //     uint48 epoch
    // ) external view returns (uint256 amount);

    // /**
    //  * @notice Get the total stake cache status for an epoch
    //  * @param epoch epoch of which to get the cache status
    //  * @return true if the total stake is cached, false otherwise
    //  */
    // function s_totalStakeCached(
    //     uint48 epoch
    // ) external view returns (bool);

    // /**
    //  * @notice Get the operator's stake amount cached for an epoch
    //  * @param epoch epoch of the related operator's stake
    //  * @param operator operator's address
    //  * @return operator's stake amount
    //  */
    // function s_operatorStakeCache(uint48 epoch, address operator) external view returns (uint256);

    // /**
    //  * @notice Registers a new operator with a key
    //  * @dev Only the owner can call this function
    //  * @param operator The operator's address
    //  * @param key The operator's key
    //  */
    // function registerOperator(address operator, bytes32 key, address(0)) external;

    // /**
    //  * @notice Updates an existing operator's key
    //  * @dev Only the owner can call this function
    //  * @param operator The operator's address
    //  * @param key The new key
    //  */
    // function updateOperatorKey(address operator, bytes32 key) external;

    // /**
    //  * @notice Pauses an operator
    //  * @dev Only the owner can call this function
    //  * @param operator The operator to pause
    //  */
    // function pauseOperator(
    //     address operator
    // ) external;

    // /**
    //  * @notice Re-enables a paused operator
    //  * @dev Only the owner can call this function
    //  * @param operator The operator to unpause
    //  */
    // function unpauseOperator(
    //     address operator
    // ) external;

    // /**
    //  * @notice Removes an operator after grace period
    //  * @dev Only the owner can call this function
    //  * @param operator The operator to unregister
    //  */
    // function unregisterOperator(
    //     address operator
    // ) external;

    // /**
    //  * @notice Registers a new vault
    //  * @dev Only the owner can call this function
    //  * @param vault The vault address to register
    //  */
    // function registerSharedVault(
    //     address vault
    // ) external;

    // /**
    //  * @notice Pauses a vault
    //  * @dev Only the owner can call this function
    //  * @param vault The vault to pause
    //  */
    // function pauseSharedVault(
    //     address vault
    // ) external;

    // /**
    //  * @notice Re-enables a paused vault
    //  * @dev Only the owner can call this function
    //  * @param vault The vault to unpause
    //  */
    // function unpauseSharedVault(
    //     address vault
    // ) external;

    // /**
    //  * @notice Removes a vault after grace period
    //  * @dev Only the owner can call this function
    //  * @param vault The vault to unregister
    //  */
    // function unregisterSharedVault(
    //     address vault
    // ) external;

    // /**
    //  * @notice Updates the number of subnetworks
    //  * @dev Only the owner can call this function
    //  * @param _subnetworksCount New subnetwork count
    //  */
    // function setSubnetworksCount(
    //     uint256 _subnetworksCount
    // ) external;

    // /**
    //  * @notice Sets the gateway contract
    //  * @dev Only the owner can call this function
    //  * @param _gateway The gateway contract address
    //  */
    // function setGateway(
    //     address _gateway
    // ) external;

    // /**
    //  * @notice Sets the rewards contracts
    //  * @param operatorRewardsAddress Address of the operator rewards contract
    //  */
    // function setOperatorRewardsContract(
    //     address operatorRewardsAddress
    // ) external;

    // /**
    //  * @notice Sets the operator share on operator rewards contract
    //  * @param operatorShare The operator share
    //  */
    // function setOperatorShareOnOperatorRewards(
    //     uint48 operatorShare
    // ) external;

    // /**
    //  * @notice Distribute rewards for a specific era contained in an epoch by providing a Merkle root, total points, total amount of tokens and the token address of the rewards.
    //  * @param epoch network epoch of the middleware
    //  * @param eraIndex era index of Starlight's rewards distribution
    //  * @param totalPointsToken total amount of points for the reward distribution
    //  * @param tokensInflatedToken amount of tokens to distribute
    //  * @param rewardsRoot Merkle root of the reward distribution
    //  * @param tokenAddress The token address of the rewards
    //  * @dev This function is called by the gateway only
    //  * @dev Emit DistributeRewards event.
    //  */
    // function distributeRewards(
    //     uint256 epoch,
    //     uint256 eraIndex,
    //     uint256 totalPointsToken,
    //     uint256 tokensInflatedToken,
    //     bytes32 rewardsRoot,
    //     address tokenAddress
    // ) external;

    // /**
    //  * @notice Calculates and caches stakes for an epoch
    //  * @param epoch The epoch to calculate for
    //  * @return totalStake The total stake amount
    //  */
    // function calcAndCacheStakes(
    //     uint48 epoch
    // ) external returns (uint256);

    // /**
    //  * @notice Slashes an operator's stake
    //  * @dev Only the owner can call this function
    //  * @dev This function first updates the stake cache for the target epoch
    //  * @param epoch The epoch number
    //  * @param operatorKey The operator key to slash
    //  * @param percentage Percentage to slash, represented as parts per billion.
    //  */
    // function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external;

    // /**
    //  * @notice Gets how many operators were active at a specific epoch
    //  * @param epoch The epoch at which to check how many operators were active
    //  * @return activeOperators The array of active operators
    //  */
    // function getOperatorsByEpoch(
    //     uint48 epoch
    // ) external view returns (address[] memory activeOperators);

    // /**
    //  * @notice Gets the operators' keys for latest epoch
    //  * @return keys Array of operator keys
    //  */
    // function sendCurrentOperatorsKeys() external returns (bytes32[] memory keys);

    // /**
    //  * @notice Gets operator-vault pairs for an epoch
    //  * @param epoch The epoch number
    //  * @return operatorVaultPairs Array of operator-vault pairs
    //  */
    // function getOperatorVaultPairs(
    //     uint48 epoch
    // ) external view returns (OperatorVaultPair[] memory operatorVaultPairs);

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

    // /**
    //  * @notice Checks if a vault is registered
    //  * @param vault The vault address to check
    //  * @return bool True if vault is registered
    //  */
    // function isVaultRegistered(
    //     address vault
    // ) external view returns (bool);

    // /**
    //  * @notice Gets operator's stake for an epoch
    //  * @param operator The operator address
    //  * @param epoch The epoch number
    //  * @return stake The operator's total stake
    //  */
    // function getOperatorStake(address operator, uint48 epoch) external view returns (uint256 stake);

    // /**
    //  * @notice Gets total stake for an epoch
    //  * @param epoch The epoch number
    //  * @return Total stake amount
    //  */
    // function getTotalStake(
    //     uint48 epoch
    // ) external view returns (uint256);

    // /**
    //  * @notice Gets validator set for an epoch
    //  * @param epoch The epoch number
    //  * @return validatorsData Array of validator data
    //  */
    // function getValidatorSet(
    //     uint48 epoch
    // ) external view returns (ValidatorData[] memory validatorsData);

    // /**
    //  * @notice Gets the timestamp when an epoch starts
    //  * @param epoch The epoch number
    //  * @return timestamp The start time of the epoch
    //  */
    // function getEpochStart(
    //     uint48 epoch
    // ) external view returns (uint48 timestamp);

    // /**
    //  * @notice Determines which epoch a timestamp belongs to
    //  * @param timestamp The timestamp to check
    //  * @return epoch The corresponding epoch number
    //  */
    // function getEpochAtTs(
    //     uint48 timestamp
    // ) external view returns (uint48 epoch);

    // /**
    //  * @notice Gets the current epoch number
    //  * @return epoch The current epoch
    //  */
    // function getCurrentEpoch() external view returns (uint48 epoch);
}
