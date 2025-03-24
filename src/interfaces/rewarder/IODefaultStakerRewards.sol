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

    /**
     * @notice Emitted when a reward is distributed.
     * @param network network on behalf of which the reward is distributed
     * @param tokenAddress address of the reward token
     * @param eraIndex era index of Starlight's rewards distribution
     * @param epoch epoch of the reward distribution
     * @param amount amount of tokens
     * @param data some used data
     */
    event DistributeRewards(
        address network,
        address indexed tokenAddress,
        uint48 indexed eraIndex,
        uint48 indexed epoch,
        uint256 amount,
        bytes data
    );

    /**
     * @notice Emitted when rewards are claimed.
     * @param network address of the network
     * @param tokenAddress address of the reward token
     * @param claimer account that claimed the reward
     * @param epoch epoch of the reward
     * @param recipient account that received the reward
     * @param lastUnclaimedReward index of the last unclaimed reward
     * @param numRewards number of rewards claimed
     * @param amount amount of tokens claimed
     */
    event ClaimRewards(
        address network,
        address indexed tokenAddress,
        address indexed claimer,
        uint48 indexed epoch,
        address recipient,
        uint256 lastUnclaimedReward,
        uint256 numRewards,
        uint256 amount
    );

    /**
     * @notice Emitted when an admin fee is claimed.
     * @param recipient account that received the fee
     * @param tokenAddress address of the reward token
     * @param amount amount of the fee claimed
     */
    event ClaimAdminFee(address indexed recipient, address indexed tokenAddress, uint256 amount);

    /**
     * @notice Emitted when an admin fee is set.
     * @param adminFee admin fee
     */
    event SetAdminFee(uint256 adminFee);

    /**
     * @notice Initial parameters needed for a staker rewards contract deployment.
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @param defaultAdminRoleHolder address of the initial DEFAULT_ADMIN_ROLE holder
     * @param adminFeeClaimRoleHolder address of the initial ADMIN_FEE_CLAIM_ROLE holder
     * @param adminFeeSetRoleHolder address of the initial ADMIN_FEE_SET_ROLE holder
     */
    struct InitParams {
        uint256 adminFee;
        address defaultAdminRoleHolder;
        address adminFeeClaimRoleHolder;
        address adminFeeSetRoleHolder;
    }

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
     * @notice Get the network middleware service's address.
     * @return address of the network middleware service
     */
    function i_networkMiddlewareService() external view returns (address);

    /**
     * @notice Get the network's address.
     * @return address of the network
     * @dev set during initalization, so it's immutable
     */
    function i_network() external view returns (address);

    /**
     * @notice Get the vault's address.
     * @return address of the vault
     * @dev set during initalization, so it's immutable
     */
    function i_vault() external view returns (address);

    /**
     * @notice Get an admin fee.
     * @return admin fee
     */
    function adminFee() external view returns (uint256);

    /**
     * @notice Get a specific reward for a given epoch.
     * @param epoch The epoch of the reward.
     * @param tokenAddress The address of the token for the specified reward.
     * @param index The index of the reward for the epoch.
     * @return amount The amount of tokens for the specified reward.
     */
    function rewards(uint48 epoch, address tokenAddress, uint256 index) external view returns (uint256 amount);

    /**
     * @notice Get the first index of the unclaimed rewards using a given epoch for a given account.
     * @param account address of the account
     * @param epoch epoch to check for unclaimed rewards
     * @param tokenAddress address of the token for the rewards
     * @return rewardIndex first index of the unclaimed rewards
     */
    function lastUnclaimedReward(
        address account,
        uint48 epoch,
        address tokenAddress
    ) external view returns (uint256 rewardIndex);

    /**
     * @notice Get a claimable admin fee amount for a given epoch.
     * @param epoch epoch for which the admin fee can be claimed
     * @param tokenAddress address of the token for the admin fee
     * @return amount claimable admin fee
     */
    function claimableAdminFee(uint48 epoch, address tokenAddress) external view returns (uint256 amount);

    /**
     * @notice Get a total number of rewards for a given epoch.
     * @param epoch epoch of the rewards
     * @param tokenAddress address of the reward token
     * @return total number of the rewards for a given epoch
     */
    function rewardsLength(uint48 epoch, address tokenAddress) external view returns (uint256);

    /**
     * @notice Get an amount of rewards claimable by a particular account for a given epoch.
     * @param epoch epoch for which the rewards can be claimed
     * @param account address of the claimer
     * @param maxRewards maximum number of rewards to claim
     * @param tokenAddress address of the reward token
     * @return amount of claimable tokens
     */
    function claimable(
        uint48 epoch,
        address account,
        uint256 maxRewards,
        address tokenAddress
    ) external view returns (uint256);

    /**
     * @notice Distribute rewards for a particular epoch
     * @param epoch epoch of the reward distribution
     * @param eraIndex era index of Starlight's rewards distribution
     * @param amount amount of tokens
     * @param tokenAddress address of the reward token
     * @param data some data to use
     */
    function distributeRewards(
        uint48 epoch,
        uint48 eraIndex,
        uint256 amount,
        address tokenAddress,
        bytes calldata data
    ) external;

    /**
     * @notice Claim rewards for a given epoch.
     * @param recipient address of the tokens' recipient
     * @param epoch epoch for which the rewards are being claimed.
     * @param tokenAddress address of the reward token
     * @param data some data to use
     */
    function claimRewards(address recipient, uint48 epoch, address tokenAddress, bytes calldata data) external;

    /**
     * @notice Claim an admin fee.
     * @param recipient account that will receive the fee
     * @param epoch epoch for which the fee is being claimed
     * @param tokenAddress address of the token for the admin fee
     * @dev Only the vault owner can call this function.
     */
    function claimAdminFee(address recipient, uint48 epoch, address tokenAddress) external;

    /**
     * @notice Set an admin fee.
     * @param adminFee admin fee (up to ADMIN_FEE_BASE inclusively)
     * @dev Only the ADMIN_FEE_SET_ROLE holder can call this function.
     */
    function setAdminFee(
        uint256 adminFee
    ) external;
}
