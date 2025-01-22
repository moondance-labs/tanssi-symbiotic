// SPDX-License-Identifier: GPL-3.0-or-later
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

interface IODefaultStakerRewards {
    error ODefaultStakerRewards__AlreadySet();
    error ODefaultStakerRewards__HighAdminFee();
    error ODefaultStakerRewards__InsufficientAdminFee();
    error ODefaultStakerRewards__InsufficientReward();
    error ODefaultStakerRewards__InvalidAdminFee();
    error ODefaultStakerRewards__InvalidHintsLength();
    error ODefaultStakerRewards__InvalidRecipient();
    error ODefaultStakerRewards__InvalidRewardTimestamp();
    error ODefaultStakerRewards__MissingRoles();
    error ODefaultStakerRewards__NoRewardsToClaim();
    error ODefaultStakerRewards__NotNetwork();
    error ODefaultStakerRewards__NotNetworkMiddleware();
    error ODefaultStakerRewards__NotVault();

    /**
     * @notice Initial parameters needed for a staker rewards contract deployment.
     * @param vault address of the vault to get stakers' data from
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @param defaultAdminRoleHolder address of the initial DEFAULT_ADMIN_ROLE holder
     * @param adminFeeClaimRoleHolder address of the initial ADMIN_FEE_CLAIM_ROLE holder
     * @param adminFeeSetRoleHolder address of the initial ADMIN_FEE_SET_ROLE holder
     */
    struct InitParams {
        address vault;
        uint256 adminFee;
        address defaultAdminRoleHolder;
        address adminFeeClaimRoleHolder;
        address adminFeeSetRoleHolder;
        address operatorRewardsRoleHolder;
    }

    /**
     * @notice Emitted when a reward is distributed.
     * @param network network on behalf of which the reward is distributed
     * @param eraIndex era index of Starlight's rewards distribution
     * @param epoch epoch of the reward distribution
     * @param amount amount of tokens
     * @param data some used data
     */
    event DistributeRewards(
        address indexed network, uint48 indexed eraIndex, uint48 indexed epoch, uint256 amount, bytes data
    );

    /**
     * @notice Emitted when rewards are claimed.
     * @param network address of the network
     * @param claimer account that claimed the reward
     * @param epoch epoch of the reward
     * @param recipient account that received the reward
     * @param firstRewardIndex first index of the claimed rewards
     * @param numRewards number of rewards claimed
     * @param amount amount of tokens claimed
     */
    event ClaimRewards(
        address indexed network,
        address indexed claimer,
        uint48 indexed epoch,
        address recipient,
        uint256 firstRewardIndex,
        uint256 numRewards,
        uint256 amount
    );

    /**
     * @notice Emitted when an admin fee is claimed.
     * @param recipient account that received the fee
     * @param amount amount of the fee claimed
     */
    event ClaimAdminFee(address indexed recipient, uint256 amount);

    /**
     * @notice Emitted when an admin fee is set.
     * @param adminFee admin fee
     */
    event SetAdminFee(uint256 adminFee);

    /**
     * @notice Get a version of the staker rewards contract (different versions mean different interfaces).
     * @return version of the staker rewards contract
     * @dev Must return 1 for this one.
     */
    function VERSION() external view returns (uint64);

    /**
     * @notice Get the maximum admin fee (= 100%).
     * @return maximum admin fee
     */
    function ADMIN_FEE_BASE() external view returns (uint256);

    /**
     * @notice Get the admin fee claimer's role.
     * @return identifier of the admin fee claimer role
     */
    function ADMIN_FEE_CLAIM_ROLE() external view returns (bytes32);

    /**
     * @notice Get the admin fee setter's role.
     * @return identifier of the admin fee setter role
     */
    function ADMIN_FEE_SET_ROLE() external view returns (bytes32);

    /**
     * @notice Get the operator rewards role.
     * @return identifier of the operator rewards role
     */
    function OPERATOR_REWARDS_ROLE() external view returns (bytes32);

    /**
     * @notice Get the vault factory's address.
     * @return address of the vault factory
     */
    function i_vaultFactory() external view returns (address);

    /**
     * @notice Get the network middleware service's address.
     * @return address of the network middleware service
     */
    function i_networkMiddlewareService() external view returns (address);

    /**
     * @notice Get the token's address.
     * @return address of the reward token
     */
    function i_token() external view returns (address);

    /**
     * @notice Get the start time of network epoch.
     * @return start time of the epoch
     */
    function i_startTime() external view returns (uint48);

    /**
     * @notice Get the duration of network epoch.
     * @return duration of the epoch
     */
    function i_epochDuration() external view returns (uint48);

    /**
     * @notice Get the network's address.
     * @return address of the network
     */
    function i_network() external view returns (address);

    /**
     * @notice Get the vault's address.
     * @return address of the vault
     */
    function s_vault() external view returns (address);

    /**
     * @notice Get an admin fee.
     * @return admin fee
     */
    function s_adminFee() external view returns (uint256);

    /**
     * @notice Get a specific reward for a given epoch.
     * @param epoch The epoch of the reward.
     * @param index The index of the reward for the epoch.
     * @return amount The amount of tokens for the specified reward.
     */
    function s_rewards(uint48 epoch, uint256 index) external view returns (uint256 amount);

    /**
     * @notice Get the first index of the unclaimed rewards using a given epoch for a given account.
     * @param account address of the account
     * @param epoch epoch to check for unclaimed rewards
     * @return first index of the unclaimed rewards
     */
    function s_lastUnclaimedReward(address account, uint48 epoch) external view returns (uint256);

    /**
     * @notice Get a claimable admin fee amount for a given epoch.
     * @param epoch epoch for which the admin fee can be claimed
     * @return claimable admin fee
     */
    function s_claimableAdminFee(
        uint48 epoch
    ) external view returns (uint256);

    /**
     * @dev Added to allow to calculate timestamp in order to access activeSharesOfAt
     * @notice Gets the timestamp when an epoch starts
     * @param epoch The epoch number
     * @return timestamp The start time of the epoch
     */
    function getEpochStartTs(
        uint48 epoch
    ) external view returns (uint48 timestamp);

    /**
     * @notice Get a total number of rewards for a given epoch.
     * @param epoch epoch of the rewards
     * @return total number of the rewards for a given epoch
     */
    function rewardsLength(
        uint48 epoch
    ) external view returns (uint256);

    /**
     * @notice Get an amount of rewards claimable by a particular account for a given epoch.
     * @param epoch epoch for which the rewards can be claimed
     * @param account address of the claimer
     * @param maxRewards maximum number of rewards to claim
     * @return amount of claimable tokens
     */
    function claimable(uint48 epoch, address account, uint256 maxRewards) external view returns (uint256);

    /**
     * @notice Distribute rewards for a particular epoch
     * @param epoch epoch of the reward distribution
     * @param eraIndex era index of Starlight's rewards distribution
     * @param amount amount of tokens
     * @param data some data to use
     */
    function distributeRewards(uint48 epoch, uint48 eraIndex, uint256 amount, bytes calldata data) external;

    /**
     * @notice Claim rewards for a given epoch.
     * @param recipient address of the tokens' recipient
     * @param epoch epoch for which the rewards are being claimed.
     * @param data some data to use
     */
    function claimRewards(address recipient, uint48 epoch, bytes calldata data) external;

    /**
     * @notice Claim an admin fee.
     * @param recipient account that will receive the fee
     * @param epoch epoch for which the fee is being claimed
     * @dev Only the vault owner can call this function.
     */
    function claimAdminFee(address recipient, uint48 epoch) external;

    /**
     * @notice Set an admin fee.
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @dev Only the ADMIN_FEE_SET_ROLE holder can call this function.
     */
    function setAdminFee(
        uint256 adminFee
    ) external;
}
