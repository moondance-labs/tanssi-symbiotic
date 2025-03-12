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
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";

contract ODefaultStakerRewards is
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    MulticallUpgradeable,
    IODefaultStakerRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultStakerRewards.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MAIN_STORAGE_LOCATION = 0xe07cde22a6017f26eee680b6867ce6727151fb6097c75742cbe379265c377400;

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultStakerRewards.v1
    struct StakerRewardsStorage {
        address NETWORK;
        address VAULT;
        uint256 adminFee;
        mapping(uint48 epoch => mapping(address tokenAddress => uint256[] rewards_)) rewards;
        mapping(address account => mapping(uint48 epoch => mapping(address tokenAddress => uint256 rewardIndex)))
            lastUnclaimedReward;
        mapping(uint48 epoch => mapping(address tokenAddress => uint256 amount)) claimableAdminFee;
        mapping(uint48 epoch => uint256 amount) activeSharesCache;
    }

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

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        $.VAULT = params.vault;
        $.NETWORK = params.network;

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
    function rewardsLength(uint48 epoch, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.rewards[epoch][tokenAddress].length;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimable(
        uint48 epoch,
        address account,
        uint256 maxRewards,
        address tokenAddress
    ) external view override returns (uint256 amount) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256[] memory rewardsPerEpoch = $.rewards[epoch][tokenAddress];
        uint256 rewardIndex = $.lastUnclaimedReward[account][epoch][tokenAddress];

        // Get the min between how many the user wants to claim and how many rewards are available
        uint256 rewardsToClaim = Math.min(maxRewards, rewardsPerEpoch.length - rewardIndex);

        uint48 epochTs = getEpochStartTs(epoch);
        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];

            amount += IVault($.VAULT).activeSharesOfAt(account, epochTs, new bytes(0)).mulDiv(
                rewardAmount, $.activeSharesCache[epoch]
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

        uint48 epochTs = getEpochStartTs(epoch);
        // If the epoch is in the future, revert
        if (epochTs >= Time.timestamp()) {
            revert ODefaultStakerRewards__InvalidRewardTimestamp();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        uint256 adminFee_ = $.adminFee;
        // If the admin fee is higher than the max allowed, revert
        if (maxAdminFee < adminFee_) {
            revert ODefaultStakerRewards__HighAdminFee();
        }

        // This is used to cache the active shares for the epoch and optimize the claiming process
        _cacheActiveShares(epoch, epochTs, activeSharesHint, activeStakeHint);

        amount = _transferAndCheckAmount(tokenAddress, amount);

        _updateAdminFeeAndRewards(amount, adminFee_, epoch, tokenAddress);

        emit DistributeRewards($.NETWORK, tokenAddress, eraIndex, epoch, amount, data);
    }

    function _transferAndCheckAmount(address tokenAddress, uint256 amount) private returns (uint256) {
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        amount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

        // Check if the amount being sent is greater than 0
        if (amount == 0) {
            revert ODefaultStakerRewards__InsufficientReward();
        }

        return amount;
    }

    function _cacheActiveShares(
        uint48 epoch,
        uint48 epochTs,
        bytes memory activeSharesHint,
        bytes memory activeStakeHint
    ) private {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        if ($.activeSharesCache[epoch] == 0) {
            uint256 activeShares_ = IVault($.VAULT).activeSharesAt(epochTs, activeSharesHint);
            uint256 activeStake_ = IVault($.VAULT).activeStakeAt(epochTs, activeStakeHint);

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert ODefaultStakerRewards__InvalidRewardTimestamp();
            }

            $.activeSharesCache[epoch] = activeShares_;
        }
    }

    function _updateAdminFeeAndRewards(uint256 amount, uint256 adminFee_, uint48 epoch, address tokenAddress) private {
        // Take out the admin fee from the rewards
        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        // And distribute the rest to the stakers
        uint256 distributeAmount = amount - adminFeeAmount;

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        $.claimableAdminFee[epoch][tokenAddress] += adminFeeAmount;

        if (distributeAmount > 0) {
            $.rewards[epoch][tokenAddress].push(distributeAmount);
        }
    }
    /**
     * @inheritdoc IODefaultStakerRewards
     */

    function claimRewards(
        address recipient,
        uint48 epoch,
        address tokenAddress,
        bytes calldata data
    ) external override nonReentrant {
        // maxRewards - the maximum amount of rewards to process
        // activeSharesOfHints - hint indexes to optimize `activeSharesOf()` processing
        (uint256 maxRewards, bytes[] memory activeSharesOfHints) = abi.decode(data, (uint256, bytes[]));

        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        (uint256 rewardsToClaim, uint256 amount, uint256 lastUnclaimedReward_) =
            _getRewardsToClaimAndAmount(epoch, tokenAddress, maxRewards, activeSharesOfHints);

        // If there are no rewards to claim, revert
        if (rewardsToClaim == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        $.lastUnclaimedReward[msg.sender][epoch][tokenAddress] = lastUnclaimedReward_ + rewardsToClaim;

        // if the amount is greater than 0, transfer the tokens to the recipient
        if (amount > 0) {
            IERC20(tokenAddress).safeTransfer(recipient, amount);
        }

        emit ClaimRewards(
            $.NETWORK, tokenAddress, msg.sender, epoch, recipient, lastUnclaimedReward_, rewardsToClaim, amount
        );
    }

    function _getRewardsToClaimAndAmount(
        uint48 epoch,
        address tokenAddress,
        uint256 maxRewards,
        bytes[] memory activeSharesOfHints
    ) private view returns (uint256 rewardsToClaim, uint256 amount, uint256 lastUnclaimedReward_) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        uint256[] memory rewardsPerEpoch = $.rewards[epoch][tokenAddress];

        // Get the last unclaimed reward index
        lastUnclaimedReward_ = $.lastUnclaimedReward[msg.sender][epoch][tokenAddress];

        // Get the min between how many the user wants to claim and how many rewards are available
        rewardsToClaim = Math.min(maxRewards, rewardsPerEpoch.length - lastUnclaimedReward_);

        if (activeSharesOfHints.length == 0) {
            activeSharesOfHints = new bytes[](rewardsToClaim);
        } else if (activeSharesOfHints.length != rewardsToClaim) {
            revert ODefaultStakerRewards__InvalidHintsLength();
        }

        // Check the total amount for the user based on his shares in the vault and update the lastUnclaimedReward_
        amount =
            _claimRewardsPerEpoch(rewardsToClaim, rewardsPerEpoch, lastUnclaimedReward_, epoch, activeSharesOfHints);
    }

    function _claimRewardsPerEpoch(
        uint256 rewardsToClaim,
        uint256[] memory rewardsPerEpoch,
        uint256 rewardIndex,
        uint48 epoch,
        bytes[] memory activeSharesOfHints
    ) private view returns (uint256 amount) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint48 epochTs = getEpochStartTs(epoch);

        for (uint256 i; i < rewardsToClaim;) {
            uint256 rewardAmount = rewardsPerEpoch[rewardIndex];

            amount += IVault($.VAULT).activeSharesOfAt(msg.sender, epochTs, activeSharesOfHints[i]).mulDiv(
                rewardAmount, $.activeSharesCache[epoch]
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
        uint48 epoch,
        address tokenAddress
    ) external nonReentrant onlyRole(ADMIN_FEE_CLAIM_ROLE) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256 claimableAdminFee_ = $.claimableAdminFee[epoch][tokenAddress];

        if (claimableAdminFee_ == 0) {
            revert ODefaultStakerRewards__InsufficientAdminFee();
        }

        $.claimableAdminFee[epoch][tokenAddress] = 0;

        IERC20(tokenAddress).safeTransfer(recipient, claimableAdminFee_);

        emit ClaimAdminFee(recipient, tokenAddress, claimableAdminFee_);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function setAdminFee(
        uint256 adminFee_
    ) external onlyRole(ADMIN_FEE_SET_ROLE) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        if ($.adminFee == adminFee_) {
            revert ODefaultStakerRewards__AlreadySet();
        }

        _setAdminFee(adminFee_);

        emit SetAdminFee(adminFee_);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function NETWORK() external view returns (address) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.NETWORK;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function VAULT() external view returns (address) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.VAULT;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function adminFee() external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.adminFee;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function rewards(uint48 epoch, address tokenAddress, uint256 index) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.rewards[epoch][tokenAddress][index];
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function lastUnclaimedReward(address account, uint48 epoch, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.lastUnclaimedReward[account][epoch][tokenAddress];
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimableAdminFee(uint48 epoch, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.claimableAdminFee[epoch][tokenAddress];
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function _setAdminFee(
        uint256 adminFee_
    ) private {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        if (adminFee_ > ADMIN_FEE_BASE) {
            revert ODefaultStakerRewards__InvalidAdminFee();
        }

        $.adminFee = adminFee_;
    }

    function _getStakerRewardsStorage() private pure returns (StakerRewardsStorage storage $) {
        bytes32 position = MAIN_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }
}
