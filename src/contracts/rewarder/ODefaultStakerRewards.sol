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

import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";
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
    uint64 public constant version = 1;

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
    address public immutable i_token;

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
    address public immutable i_network;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public s_vault;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint256 public s_adminFee;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(uint48 epoch => uint256[] rewards_) public s_rewards;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address account => mapping(uint48 epoch => uint256 rewardIndex)) public s_lastUnclaimedReward;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(uint48 epoch => uint256 amount) public s_claimableAdminFee;

    mapping(uint48 epoch => uint256 amount) private _s_activeSharesCache;

    constructor(
        address network,
        address vaultFactory,
        address networkMiddlewareService,
        uint48 startTime,
        uint48 epochDuration,
        address token,
        InitParams memory params
    ) {
        i_network = network;
        i_vaultFactory = vaultFactory;
        i_networkMiddlewareService = networkMiddlewareService;
        i_startTime = startTime;
        i_epochDuration = epochDuration;
        i_token = token;

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

        s_vault = params.vault;

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
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return i_startTime + epoch * i_epochDuration;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function rewardsLength(
        uint48 epoch
    ) external view returns (uint256) {
        return s_rewards[epoch].length;
    }

    function setVault(
        address vault
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (s_vault == vault) {
            revert ODefaultStakerRewards__AlreadySet();
        }
        if (!IRegistry(i_vaultFactory).isEntity(vault)) {
            revert ODefaultStakerRewards__NotVault();
        }
        s_vault = vault;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimable(
        uint48 epoch,
        address account,
        uint256 maxRewards
    ) external view override returns (uint256 amount) {
        uint256[] memory rewardsPerEpoch = s_rewards[epoch];
        uint256 rewardIndex = s_lastUnclaimedReward[account][epoch];

        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerEpoch.length - rewardIndex);
        uint48 epochTs = getEpochStartTs(epoch);
        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];

            amount += IVault(s_vault).activeSharesOfAt(account, epochTs, new bytes(0)).mulDiv(
                rewardAmount, _s_activeSharesCache[epoch]
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
        uint48 epoch,
        uint256 amount,
        bytes calldata data
    ) external override nonReentrant onlyRole(OPERATOR_REWARDS_ROLE) {
        //! TODO This should be restricted to operator rewards
        // maxAdminFee - the maximum admin fee to allow
        // activeSharesHint - a hint index to optimize `activeSharesAt()` processing
        // activeStakeHint - a hint index to optimize `activeStakeAt()` processing
        (uint256 maxAdminFee, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(data, (uint256, bytes, bytes));

        uint48 epochTs = getEpochStartTs(epoch);
        if (epochTs >= Time.timestamp()) {
            revert ODefaultStakerRewards__InvalidRewardTimestamp();
        }

        uint256 adminFee_ = s_adminFee;
        if (maxAdminFee < adminFee_) {
            revert ODefaultStakerRewards__HighAdminFee();
        }

        if (_s_activeSharesCache[epoch] == 0) {
            uint256 activeShares_ = IVault(s_vault).activeSharesAt(epochTs, activeSharesHint);
            uint256 activeStake_ = IVault(s_vault).activeStakeAt(epochTs, activeStakeHint);

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert ODefaultStakerRewards__InvalidRewardTimestamp();
            }

            _s_activeSharesCache[epoch] = activeShares_;
        }

        uint256 balanceBefore = IERC20(i_token).balanceOf(address(this));
        IERC20(i_token).safeTransferFrom(msg.sender, address(this), amount);
        amount = IERC20(i_token).balanceOf(address(this)) - balanceBefore;

        if (amount == 0) {
            revert ODefaultStakerRewards__InsufficientReward();
        }

        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        uint256 distributeAmount = amount - adminFeeAmount;

        s_claimableAdminFee[epoch] += adminFeeAmount;

        if (distributeAmount > 0) {
            s_rewards[epoch].push(distributeAmount);
        }

        emit DistributeRewards(i_network, amount, data);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(address recipient, uint48 epoch, bytes calldata data) external override nonReentrant {
        // maxRewards - the maximum amount of rewards to process
        // activeSharesOfHints - hint indexes to optimize `activeSharesOf()` processing
        (uint256 maxRewards, bytes[] memory activeSharesOfHints) = abi.decode(data, (uint256, bytes[]));

        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }

        uint256[] memory rewardsPerEpoch = s_rewards[epoch];
        uint256 lastUnclaimedReward_ = s_lastUnclaimedReward[msg.sender][epoch];

        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerEpoch.length - lastUnclaimedReward_);

        if (rewardsToClaim == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        if (activeSharesOfHints.length == 0) {
            activeSharesOfHints = new bytes[](rewardsToClaim);
        } else if (activeSharesOfHints.length != rewardsToClaim) {
            revert ODefaultStakerRewards__InvalidHintsLength();
        }

        //! TODO Should we add that rewards are gonna expire after 1 month?

        uint256 rewardIndex = lastUnclaimedReward_;
        uint256 amount = _claimRewardsPerEpoch(rewardsToClaim, rewardsPerEpoch, rewardIndex, epoch, activeSharesOfHints);

        s_lastUnclaimedReward[msg.sender][epoch] = rewardIndex;

        if (amount > 0) {
            IERC20(i_token).safeTransfer(recipient, amount);
        }

        emit ClaimRewards(i_network, msg.sender, epoch, recipient, lastUnclaimedReward_, rewardsToClaim, amount);
    }

    function _claimRewardsPerEpoch(
        uint256 rewardsToClaim,
        uint256[] memory rewardsPerEpoch,
        uint256 rewardIndex,
        uint48 epoch,
        bytes[] memory activeSharesOfHints
    ) private view returns (uint256 amount) {
        uint48 epochTs = getEpochStartTs(epoch);
        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];
            amount += IVault(s_vault).activeSharesOfAt(msg.sender, epochTs, activeSharesOfHints[i]).mulDiv(
                rewardAmount, _s_activeSharesCache[epoch]
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

    function claimAdminFee(address recipient, uint48 epoch) external nonReentrant onlyRole(ADMIN_FEE_CLAIM_ROLE) {
        uint256 claimableAdminFee_ = s_claimableAdminFee[epoch];
        if (claimableAdminFee_ == 0) {
            revert ODefaultStakerRewards__InsufficientAdminFee();
        }

        s_claimableAdminFee[epoch] = 0;

        IERC20(i_token).safeTransfer(recipient, claimableAdminFee_);

        emit ClaimAdminFee(recipient, claimableAdminFee_);
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
