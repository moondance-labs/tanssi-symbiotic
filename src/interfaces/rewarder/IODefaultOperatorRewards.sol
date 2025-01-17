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

interface IODefaultOperatorRewards {
    error ODefaultOperatorRewards__InsufficientBalance();
    error ODefaultOperatorRewards__InsufficientTotalClaimable();
    error ODefaultOperatorRewards__InsufficientTransfer();
    error ODefaultOperatorRewards__InvalidProof();
    error ODefaultOperatorRewards__NotNetworkMiddleware();
    error ODefaultOperatorRewards__RootNotSet();
    error ODefaultOperatorRewards__InvalidTotalPoints();
    error ODefaultOperatorRewards__InvalidOperatorShare();
    error ODefaultOperatorRewards__AlreadySet();

    /**
     * @notice Emitted when rewards are distributed by providing a Merkle root.
     * @param epoch epoch of the rewards distribution
     * @param root Merkle root of the rewards distribution
     * @dev The Merkle tree's leaves must represent an account and a claimable amount (the total amount of the reward tokens for the whole time).
     */
    event DistributeRewards(uint48 indexed epoch, bytes32 indexed root);

    /**
     * @notice Emitted when rewards are claimed by a particular account.
     * @param recipient address of the rewards' recipient
     * @param epoch epoch for which the rewards are claimed
     * @param claimer address of the rewards' claimer
     * @param amount amount of tokens claimed
     */
    event ClaimRewards(address indexed recipient, uint48 indexed epoch, address indexed claimer, uint256 amount);

    /**
     * @notice Struct to store the amount of tokens received per epoch and the amount of tokens per point.
     * @param amount amount of tokens received per epoch
     * @param tokensPerPoint amount of tokens per point
     */
    struct BalancePerEpoch {
        uint256 amount;
        uint256 tokensPerPoint;
    }

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
     * @notice Get the network identifier.
     * @return network identifier
     */
    function i_network() external view returns (address);

    /**
     * @notice Get the default staker rewards contract's address.
     * @return address of the default staker rewards contract
     */
    function s_defaultStakerRewards() external view returns (address);

    /**
     * @notice Get the operator share.
     * @return operator share
     */
    function s_operatorShare() external view returns (uint48);

    /**
     * @notice Get a Merkle root of a reward distribution for a particular epoch.
     * @param epoch epoch of the reward distribution
     * @return Merkle root of the reward distribution
     */
    function s_epochRoot(
        uint48 epoch
    ) external view returns (bytes32);

    /**
     * @notice Get an amount of tokens that can be claimed for a particular epoch.
     * @param epoch epoch of the related available rewards
     * @return amount of tokens that can be claimed
     * @return tokensPerPoints amount of tokens per point
     */
    function s_balance(
        uint48 epoch
    ) external view returns (uint256 amount, uint256 tokensPerPoints);

    /**
     * @notice Get a claimed amount of rewards for a particular account and epoch
     * @param epoch epoch of the related claimed rewards
     * @param account address of the claimer
     * @return claimed amount of tokens
     */
    function s_claimed(uint48 epoch, address account) external view returns (uint256);

    /**
     * @notice Distribute rewards by providing a Merkle root.
     * @param epoch epoch of the rewards distribution
     * @param amount amount of tokens to distribute
     * @param root Merkle root of the reward distribution
     */
    function distributeRewards(uint48 epoch, uint256 amount, uint256 totalPointsToken, bytes32 root) external;

    /**
     * @notice Claim rewards for a particular epoch by providing a Merkle proof.
     * @param operatorKey operator key of the rewards' recipient
     * @param epoch epoch for which the rewards are claimed
     * @param totalClaimable total amount of tokens that can be claimed
     * @param proof Merkle proof of the reward distribution
     * @param data additional data to use to distribute rewards to stakers
     * @return amount amount of tokens claimed
     */
    function claimRewards(
        bytes32 operatorKey,
        uint48 epoch,
        uint32 totalClaimable,
        bytes32[] calldata proof,
        bytes calldata data
    ) external returns (uint256 amount);
}
