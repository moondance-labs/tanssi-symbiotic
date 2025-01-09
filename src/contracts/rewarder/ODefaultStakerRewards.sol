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

    address public s_network;

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
        address vaultFactory,
        address networkMiddlewareService,
        uint48 startTime,
        uint48 epochDuration,
        address token
    ) {
        // probably we don't need this since we will just deploy it and upgrade it and we don't need a factory
        // _disableInitializers();

        i_vaultFactory = vaultFactory;
        i_networkMiddlewareService = networkMiddlewareService;
        i_startTime = startTime;
        i_epochDuration = epochDuration;
        i_token = token;
    }

    /**
     * @dev Added to allow to calculate timestamp in order to access activeSharesOfAt
     * @notice Gets the timestamp when an epoch starts
     * @param epoch The epoch number
     * @return timestamp The start time of the epoch
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

        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];

            amount += IVault(s_vault).activeSharesOfAt(account, epoch, new bytes(0)).mulDiv(
                rewardAmount, _s_activeSharesCache[epoch]
            );

            unchecked {
                ++i;
                ++rewardIndex;
            }
        }
    }

    //! Probably to take out as stated above
    function initialize(
        InitParams calldata params
    ) external initializer {
        if (!IRegistry(i_vaultFactory).isEntity(params.vault)) {
            revert NotVault();
        }

        if (params.defaultAdminRoleHolder == address(0)) {
            if (params.adminFee == 0) {
                if (params.adminFeeClaimRoleHolder == address(0)) {
                    if (params.adminFeeSetRoleHolder != address(0)) {
                        revert MissingRoles();
                    }
                } else if (params.adminFeeSetRoleHolder == address(0)) {
                    revert MissingRoles();
                }
            } else if (params.adminFeeClaimRoleHolder == address(0)) {
                revert MissingRoles();
            }
        }

        __ReentrancyGuard_init();

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
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function distributeRewards(uint48 epoch, uint256 amount, bytes calldata data) external override nonReentrant {
        // maxAdminFee - the maximum admin fee to allow
        // activeSharesHint - a hint index to optimize `activeSharesAt()` processing
        // activeStakeHint - a hint index to optimize `activeStakeAt()` processing

        (uint256 maxAdminFee, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(data, (uint256, bytes, bytes));

        uint48 epochTs = getEpochStartTs(epoch);

        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(s_network) != msg.sender) {
            revert NotNetworkMiddleware();
        }

        if (epoch >= Time.timestamp()) {
            revert InvalidRewardTimestamp();
        }

        uint256 adminFee_ = s_adminFee;
        if (maxAdminFee < adminFee_) {
            revert HighAdminFee();
        }

        if (_s_activeSharesCache[epoch] == 0) {
            uint256 activeShares_ = IVault(s_vault).activeSharesAt(epochTs, activeSharesHint);
            uint256 activeStake_ = IVault(s_vault).activeStakeAt(epochTs, activeStakeHint);

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert InvalidRewardTimestamp();
            }

            _s_activeSharesCache[epoch] = activeShares_;
        }

        //!Comment 3 Probably mint and then transfer on distribute or claim?
        uint256 balanceBefore = IERC20(i_token).balanceOf(address(this));
        IERC20(i_token).safeTransferFrom(msg.sender, address(this), amount);
        amount = IERC20(i_token).balanceOf(address(this)) - balanceBefore;

        if (amount == 0) {
            revert InsufficientReward();
        }

        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        uint256 distributeAmount = amount - adminFeeAmount;

        s_claimableAdminFee[epoch] += adminFeeAmount;

        if (distributeAmount > 0) {
            s_rewards[epoch].push(distributeAmount);
        }

        emit DistributeRewards(s_network, amount, data);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(address recipient, uint48 epoch, bytes calldata data) external override nonReentrant {
        // maxRewards - the maximum amount of rewards to process
        // activeSharesOfHints - hint indexes to optimize `activeSharesOf()` processing
        (uint256 maxRewards, bytes[] memory activeSharesOfHints) = abi.decode(data, (uint256, bytes[]));

        if (recipient == address(0)) {
            revert InvalidRecipient();
        }

        uint256[] memory rewardsPerEpoch = s_rewards[epoch];
        uint256 lastUnclaimedReward_ = s_lastUnclaimedReward[msg.sender][epoch];

        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerEpoch.length - lastUnclaimedReward_);

        if (rewardsToClaim == 0) {
            revert NoRewardsToClaim();
        }

        if (activeSharesOfHints.length == 0) {
            activeSharesOfHints = new bytes[](rewardsToClaim);
        } else if (activeSharesOfHints.length != rewardsToClaim) {
            revert InvalidHintsLength();
        }

        //!Comment 1 Should we add that rewards are gonna expire after 1 month?
        uint256 amount;
        uint256 rewardIndex = lastUnclaimedReward_;
        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];
            uint48 epochTs = getEpochStartTs(epoch);
            amount += IVault(s_vault).activeSharesOfAt(msg.sender, epochTs, activeSharesOfHints[i]).mulDiv(
                rewardAmount, _s_activeSharesCache[epoch]
            );

            unchecked {
                ++i;
                ++rewardIndex;
                rewardsPerEpoch;
            }
        }

        s_lastUnclaimedReward[msg.sender][epoch] = rewardIndex;

        if (amount > 0) {
            //!Comment 2 Mint and then transfer?
            IERC20(i_token).safeTransfer(recipient, amount);
        }

        emit ClaimRewards(s_network, msg.sender, epoch, recipient, lastUnclaimedReward_, rewardsToClaim, amount);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimAdminFee(address recipient, uint48 epoch) external nonReentrant onlyRole(ADMIN_FEE_CLAIM_ROLE) {
        uint256 claimableAdminFee_ = s_claimableAdminFee[epoch];
        if (claimableAdminFee_ == 0) {
            revert InsufficientAdminFee();
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
            revert AlreadySet();
        }

        _setAdminFee(adminFee_);

        emit SetAdminFee(adminFee_);
    }

    function _setAdminFee(
        uint256 adminFee_
    ) private {
        if (adminFee_ > ADMIN_FEE_BASE) {
            revert InvalidAdminFee();
        }

        s_adminFee = adminFee_;
    }
}
