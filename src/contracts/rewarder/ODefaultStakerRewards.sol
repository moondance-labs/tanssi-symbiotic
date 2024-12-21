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
     * @inheritdoc IStakerRewards
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
    uint48 public immutable i_startTime;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint48 public immutable i_epochDuration;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public s_vault;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    uint256 public adminFee;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address token => mapping(address network => RewardDistribution[] rewards_)) public rewards;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address account => mapping(address token => mapping(address network => uint256 rewardIndex))) public
        lastUnclaimedReward;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    mapping(address token => uint256 amount) public claimableAdminFee;

    mapping(uint48 timestamp => uint256 amount) private _activeSharesCache;

    constructor(address vaultFactory, address networkMiddlewareService, uint48 startTime, uint48 epochDuration) {
        // probably we don't need this since we will just deploy it and upgrade it and we don't need a factory
        // _disableInitializers();

        i_vaultFactory = vaultFactory;
        i_networkMiddlewareService = networkMiddlewareService;
        i_startTime = startTime;
        i_epochDuration = epochDuration;
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
    function rewardsLength(address token, address network) external view returns (uint256) {
        return rewards[token][network].length;
    }

    /**
     * @inheritdoc IStakerRewards
     */
    function claimable(
        address token,
        address account,
        bytes calldata data
    ) external view override returns (uint256 amount) {
        // network - a network to claim rewards for
        // maxRewards - the maximum amount of rewards to process
        (address network, uint256 maxRewards) = abi.decode(data, (address, uint256));

        RewardDistribution[] storage rewardsByTokenNetwork = rewards[token][network];
        uint256 rewardIndex = lastUnclaimedReward[account][token][network];

        uint256 rewardsToClaim = Math.min(maxRewards, rewardsByTokenNetwork.length - rewardIndex);

        //! Probably this whole part needs to be changed.
        for (uint256 i; i < rewardsToClaim;) {
            RewardDistribution storage reward = rewardsByTokenNetwork[rewardIndex];

            amount += IVault(s_vault).activeSharesOfAt(account, reward.epoch, new bytes(0)).mulDiv(
                reward.amount, _activeSharesCache[reward.epoch]
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
     * @inheritdoc IStakerRewards
     */
    function distributeRewards(
        address network,
        address token,
        uint256 amount,
        bytes calldata data
    ) external override nonReentrant {
        // epoch - an epoch at which stakes must be taken into account
        // root - a Merkle root of the epoch
        // maxAdminFee - the maximum admin fee to allow
        // activeSharesHint - a hint index to optimize `activeSharesAt()` processing
        // activeStakeHint - a hint index to optimize `activeStakeAt()` processing

        (uint48 epoch, bytes32 root, uint256 maxAdminFee, bytes memory activeSharesHint, bytes memory activeStakeHint) =
            abi.decode(data, (uint48, bytes32, uint256, bytes, bytes));

        uint48 epochTs = getEpochStartTs(epoch);

        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(network) != msg.sender) {
            revert NotNetworkMiddleware();
        }

        if (epoch >= Time.timestamp()) {
            revert InvalidRewardTimestamp();
        }

        uint256 adminFee_ = adminFee;
        if (maxAdminFee < adminFee_) {
            revert HighAdminFee();
        }

        if (_activeSharesCache[epoch] == 0) {
            uint256 activeShares_ = IVault(s_vault).activeSharesAt(epochTs, activeSharesHint);
            uint256 activeStake_ = IVault(s_vault).activeStakeAt(epochTs, activeStakeHint);

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert InvalidRewardTimestamp();
            }

            _activeSharesCache[epoch] = activeShares_;
        }

        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        amount = IERC20(token).balanceOf(address(this)) - balanceBefore;

        if (amount == 0) {
            revert InsufficientReward();
        }

        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        uint256 distributeAmount = amount - adminFeeAmount;

        claimableAdminFee[token] += adminFeeAmount;

        if (distributeAmount > 0) {
            rewards[token][network].push(RewardDistribution({amount: distributeAmount, epoch: epoch, root: root}));
        }

        emit DistributeRewards(network, token, amount, data);
    }

    /**
     * @inheritdoc IStakerRewards
     */
    function claimRewards(address recipient, address token, bytes calldata data) external override nonReentrant {
        // network - a network to claim rewards for
        // maxRewards - the maximum amount of rewards to process
        // activeSharesOfHints - hint indexes to optimize `activeSharesOf()` processing
        (address network, uint256 maxRewards, bytes[] memory activeSharesOfHints) =
            abi.decode(data, (address, uint256, bytes[]));

        if (recipient == address(0)) {
            revert InvalidRecipient();
        }

        RewardDistribution[] storage rewardsByTokenNetwork = rewards[token][network];
        uint256 lastUnclaimedReward_ = lastUnclaimedReward[msg.sender][token][network];

        uint256 rewardsToClaim = Math.min(maxRewards, rewardsByTokenNetwork.length - lastUnclaimedReward_);

        if (rewardsToClaim == 0) {
            revert NoRewardsToClaim();
        }

        if (activeSharesOfHints.length == 0) {
            activeSharesOfHints = new bytes[](rewardsToClaim);
        } else if (activeSharesOfHints.length != rewardsToClaim) {
            revert InvalidHintsLength();
        }

        //! This calculates the rewards based on activeSharesOfAt, but we want based on the root. Follow
        //  if (
        //     !MerkleProof.verifyCalldata(
        //         proof, root_, keccak256(bytes.concat(keccak256(abi.encode(msg.sender, totalClaimable))))
        //     )
        // ) {
        //     revert InvalidProof();
        // }
        //! Should we add that rewards are gonna expire after 1 month?
        uint256 amount;
        uint256 rewardIndex = lastUnclaimedReward_;
        for (uint256 i; i < rewardsToClaim;) {
            RewardDistribution storage reward = rewardsByTokenNetwork[rewardIndex];
            uint48 epochTs = getEpochStartTs(reward.epoch);
            amount += IVault(s_vault).activeSharesOfAt(msg.sender, epochTs, activeSharesOfHints[i]).mulDiv(
                reward.amount, _activeSharesCache[reward.epoch]
            );

            unchecked {
                ++i;
                ++rewardIndex;
            }
        }

        lastUnclaimedReward[msg.sender][token][network] = rewardIndex;

        if (amount > 0) {
            IERC20(token).safeTransfer(recipient, amount);
        }

        emit ClaimRewards(token, network, msg.sender, recipient, lastUnclaimedReward_, rewardsToClaim, amount);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimAdminFee(address recipient, address token) external nonReentrant onlyRole(ADMIN_FEE_CLAIM_ROLE) {
        uint256 claimableAdminFee_ = claimableAdminFee[token];
        if (claimableAdminFee_ == 0) {
            revert InsufficientAdminFee();
        }

        claimableAdminFee[token] = 0;

        IERC20(token).safeTransfer(recipient, claimableAdminFee_);

        emit ClaimAdminFee(token, claimableAdminFee_);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function setAdminFee(
        uint256 adminFee_
    ) external onlyRole(ADMIN_FEE_SET_ROLE) {
        if (adminFee == adminFee_) {
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

        adminFee = adminFee_;
    }
}
