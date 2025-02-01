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

pragma solidity 0.8.25;

import {console2} from "forge-std/console2.sol";
// *********************************************************************************************************************
//                                                  SYMBIOTIC
// *********************************************************************************************************************
import {IStakerRewards} from "@symbiotic-rewards/interfaces/stakerRewards/IStakerRewards.sol";
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";

// *********************************************************************************************************************
//                                                  OPENZEPPELIN
// *********************************************************************************************************************
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {MulticallUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";

contract ODefaultStakerRewards is
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    MulticallUpgradeable,
    IODefaultStakerRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint64 public constant VERSION = 1;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint256 public constant ADMIN_FEE_BASE = 10_000;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    bytes32 public constant ADMIN_FEE_CLAIM_ROLE = keccak256("ADMIN_FEE_CLAIM_ROLE");

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    bytes32 public constant ADMIN_FEE_SET_ROLE = keccak256("ADMIN_FEE_SET_ROLE");

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    bytes32 public constant OPERATOR_REWARDS_ROLE = keccak256("OPERATOR_REWARDS_ROLE");

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public immutable i_vaultFactory;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint48 public immutable i_startTime;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint48 public immutable i_epochDuration;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public NETWORK;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public VAULT;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint256 public s_adminFee;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address tokenAddress => Reward[] rewards_) public s_rewards;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address account => mapping(address tokenAddress => uint256 rewardIndex)) public s_lastUnclaimedReward;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address tokenAddress => uint256 amount) public s_claimableAdminFee;

    mapping(uint48 timestamp => uint256 amount) private _s_activeSharesCache;

    constructor(address vaultFactory, address networkMiddlewareService, uint48 startTime, uint48 epochDuration) {
        _disableInitializers();

        i_vaultFactory = vaultFactory;
        i_networkMiddlewareService = networkMiddlewareService;
        i_startTime = startTime;
        i_epochDuration = epochDuration;
    }

    function initialize(
        InitParams calldata params
    ) external initializer {
        if (!IRegistry(i_vaultFactory).isEntity(params.vault)) {
            revert ODefaultStakerRewards__NotVault();
        }

        if (params.defaultAdminRoleHolder == address(0)) {
            if (params.adminFee == 0) {
                if (params.adminFeeClaimRoleHolder == address(0)) {
                    if (params.adminFeeSetRoleHolder != address(0)) {
                        revert ODefaultStakerRewards__MissingRoles();
                    }
                } else if (params.adminFeeSetRoleHolder == address(0)) {
                    revert ODefaultStakerRewards__MissingRoles();
                }
            } else if (params.adminFeeClaimRoleHolder == address(0)) {
                revert ODefaultStakerRewards__MissingRoles();
            }
        }

        if (params.operatorRewardsRoleHolder == address(0)) {
            revert ODefaultStakerRewards__MissingRoles();
        }

        __ReentrancyGuard_init();

        VAULT = params.vault;
        NETWORK = params.network;

        _setAdminFee(params.adminFee);

        if (params.defaultAdminRoleHolder != address(0)) {
            _grantRole(DEFAULT_ADMIN_ROLE, params.defaultAdminRoleHolder);
        }
        if (params.adminFeeClaimRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_CLAIM_ROLE, params.adminFeeClaimRoleHolder);
        }
        if (params.adminFeeSetRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_SET_ROLE, params.adminFeeSetRoleHolder);
        }
        if (params.operatorRewardsRoleHolder != address(0)) {
            _grantRole(OPERATOR_REWARDS_ROLE, params.operatorRewardsRoleHolder);
        }
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function rewardsLength(
        address tokenAddress
    ) external view returns (uint256) {
        return s_rewards[tokenAddress].length;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimable(
        address tokenAddress,
        address account,
        uint256 maxRewards
    ) external view override returns (uint256 amount) {
        Reward[] memory rewardsPerToken = s_rewards[tokenAddress];
        uint256 rewardIndex = s_lastUnclaimedReward[account][tokenAddress];

        // Get the min between how many the user wants to claim and how many rewards are available
        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerToken.length - rewardIndex);

        for (uint256 i; i < rewardsToClaim;) {
            Reward memory reward = rewardsPerToken[rewardIndex];

            amount += IVault(VAULT).activeSharesOfAt(account, reward.timestamp, new bytes(0)).mulDiv(
                reward.amount, _s_activeSharesCache[reward.timestamp]
            );

            unchecked {
                ++i;
                ++rewardIndex;
            }
        }
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function distributeRewards(
        uint48 timestamp,
        uint48 eraIndex,
        uint256 amount,
        address tokenAddress,
        bytes calldata data
    ) external override nonReentrant onlyRole(OPERATOR_REWARDS_ROLE) {
        // maxAdminFee - the maximum admin fee to allow
        // activeSharesHint - a hint index to optimize `activeSharesAt()` processing
        // activeStakeHint - a hint index to optimize `activeStakeAt()` processing
        (uint256 maxAdminFee, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(data, (uint256, bytes, bytes));

        console2.log("distributeRewards", timestamp, Time.timestamp());
        // If the timestamp is in the future, revert
        if (timestamp >= Time.timestamp()) {
            revert ODefaultStakerRewards__InvalidRewardTimestamp();
        }

        uint256 adminFee_ = s_adminFee;
        // If the admin fee is higher than the max allowed, revert
        if (maxAdminFee < adminFee_) {
            revert ODefaultStakerRewards__HighAdminFee();
        }

        // This is used to cache the active shares for the timestamp and optimize the claiming process
        _cacheActiveShares(timestamp, activeSharesHint, activeStakeHint);

        // Check if the amount being sent is greater than 0
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        amount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

        if (amount == 0) {
            revert ODefaultStakerRewards__InsufficientReward();
        }

        _updateAdminFeeAndRewards(amount, adminFee_, timestamp, tokenAddress);

        emit DistributeRewards(tokenAddress, eraIndex, timestamp, NETWORK, amount, data);
    }

    function _cacheActiveShares(
        uint48 timestamp,
        bytes memory activeSharesHint,
        bytes memory activeStakeHint
    ) private {
        console2.log("cacheActiveShares", timestamp, _s_activeSharesCache[timestamp]);
        if (_s_activeSharesCache[timestamp] == 0) {
            uint256 activeShares_ = IVault(VAULT).activeSharesAt(timestamp, activeSharesHint);
            uint256 activeStake_ = IVault(VAULT).activeStakeAt(timestamp, activeStakeHint);

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert ODefaultStakerRewards__InvalidRewardTimestamp();
            }

            _s_activeSharesCache[timestamp] = activeShares_;
        }
    }

    function _updateAdminFeeAndRewards(
        uint256 amount,
        uint256 adminFee_,
        uint48 timestamp,
        address tokenAddress
    ) private {
        // Take out the admin fee from the rewards
        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        // And distribute the rest to the stakers
        uint256 distributeAmount = amount - adminFeeAmount;

        s_claimableAdminFee[tokenAddress] += adminFeeAmount;

        if (distributeAmount > 0) {
            Reward memory reward = Reward({amount: distributeAmount, timestamp: timestamp});
            s_rewards[tokenAddress].push(reward);
        }
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(
        address recipient,
        address tokenAddress,
        bytes calldata data
    ) external override nonReentrant {
        // maxRewards - the maximum amount of rewards to process
        // activeSharesOfHints - hint indexes to optimize `activeSharesOf()` processing
        (uint256 maxRewards, bytes[] memory activeSharesOfHints) = abi.decode(data, (uint256, bytes[]));

        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }

        Reward[] memory rewardsPerToken = s_rewards[tokenAddress];

        // Get the last unclaimed reward index
        uint256 lastUnclaimedReward_ = s_lastUnclaimedReward[msg.sender][tokenAddress];

        // Get the min between how many the user wants to claim and how many rewards are available
        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerToken.length - lastUnclaimedReward_);

        // If there are no rewards to claim, revert
        if (rewardsToClaim == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        if (activeSharesOfHints.length == 0) {
            activeSharesOfHints = new bytes[](rewardsToClaim);
        } else if (activeSharesOfHints.length != rewardsToClaim) {
            revert ODefaultStakerRewards__InvalidHintsLength();
        }

        // Check the total amount for the user based on his shares in the vault and update the lastUnclaimedReward_
        uint256 amount =
            _claimRewardsPerEpoch(rewardsToClaim, rewardsPerToken, lastUnclaimedReward_, activeSharesOfHints);

        s_lastUnclaimedReward[msg.sender][tokenAddress] = lastUnclaimedReward_;

        // if the amount is greater than 0, transfer the tokens to the recipient
        if (amount > 0) {
            IERC20(tokenAddress).safeTransfer(recipient, amount);
        }

        emit ClaimRewards(tokenAddress, msg.sender, NETWORK, recipient, lastUnclaimedReward_, rewardsToClaim, amount);
    }

    function _claimRewardsPerEpoch(
        uint256 rewardsToClaim,
        Reward[] memory rewardsPerToken,
        uint256 rewardIndex,
        bytes[] memory activeSharesOfHints
    ) private view returns (uint256 amount) {
        for (uint256 i; i < rewardsToClaim;) {
            Reward memory reward = rewardsPerToken[rewardIndex];

            amount += IVault(VAULT).activeSharesOfAt(msg.sender, reward.timestamp, activeSharesOfHints[i]).mulDiv(
                reward.amount, _s_activeSharesCache[reward.timestamp]
            );

            unchecked {
                ++i;
                ++rewardIndex;
            }
        }
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimAdminFee(
        address recipient,
        address tokenAddress
    ) external nonReentrant onlyRole(ADMIN_FEE_CLAIM_ROLE) {
        uint256 claimableAdminFee_ = s_claimableAdminFee[tokenAddress];

        if (claimableAdminFee_ == 0) {
            revert ODefaultStakerRewards__InsufficientAdminFee();
        }

        s_claimableAdminFee[tokenAddress] = 0;

        IERC20(tokenAddress).safeTransfer(recipient, claimableAdminFee_);

        emit ClaimAdminFee(recipient, tokenAddress, claimableAdminFee_);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function setAdminFee(
        uint256 adminFee_
    ) external onlyRole(ADMIN_FEE_SET_ROLE) {
        if (s_adminFee == adminFee_) {
            revert ODefaultStakerRewards__AlreadySet();
        }

        _setAdminFee(adminFee_);

        emit SetAdminFee(adminFee_);
    }

    function _setAdminFee(
        uint256 adminFee_
    ) private {
        if (adminFee_ > ADMIN_FEE_BASE) {
            revert ODefaultStakerRewards__InvalidAdminFee();
        }

        s_adminFee = adminFee_;
    }
}
