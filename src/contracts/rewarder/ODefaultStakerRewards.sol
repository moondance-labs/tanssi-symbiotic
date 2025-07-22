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
import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
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

import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

contract ODefaultStakerRewards is
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    MulticallUpgradeable,
    IODefaultStakerRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultStakerRewards.v1.1
    struct StakerRewardsStorage {
        uint256 adminFee;
        mapping(uint48 epoch => mapping(address tokenAddress => uint256 rewards_)) rewards;
        mapping(address account => mapping(uint48 epoch => mapping(address tokenAddress => uint256 claimed)))
            stakerClaimedRewardPerEpoch;
        mapping(uint48 epoch => mapping(address tokenAddress => uint256 amount)) claimableAdminFee;
        mapping(uint48 epoch => uint256 amount) activeSharesCache;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultStakerRewards.v1.1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STAKER_REWARDS_STORAGE_LOCATION =
        0xef473712465551821e7a51c85c06a1bf76bdf2a3508e28184170ac7eb0322c00;

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
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public immutable i_network;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public i_vault;

    constructor(address networkMiddlewareService, address network) {
        _disableInitializers();

        if (network == address(0) || networkMiddlewareService == address(0)) {
            revert ODefaultStakerRewards__InvalidAddress();
        }
        i_networkMiddlewareService = networkMiddlewareService;
        i_network = network;
    }

    function initialize(address operatorRewards, address vault_, InitParams calldata params) external initializer {
        if (operatorRewards == address(0) || vault_ == address(0)) {
            revert ODefaultStakerRewards__InvalidAddress();
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

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _setAdminFee(params.adminFee);

        i_vault = vault_;

        if (params.defaultAdminRoleHolder != address(0)) {
            _grantRole(DEFAULT_ADMIN_ROLE, params.defaultAdminRoleHolder);
        }
        if (params.adminFeeClaimRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_CLAIM_ROLE, params.adminFeeClaimRoleHolder);
        }
        if (params.adminFeeSetRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_SET_ROLE, params.adminFeeSetRoleHolder);
        }
        _grantRole(OPERATOR_REWARDS_ROLE, operatorRewards);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimable(
        uint48 epoch,
        address account,
        address tokenAddress
    ) external view override returns (uint256 amount) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256 rewardsPerEpoch = $.rewards[epoch][tokenAddress];
        uint256 claimedPerEpoch = $.stakerClaimedRewardPerEpoch[account][epoch][tokenAddress];

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);

        amount = IVault(i_vault).activeSharesOfAt(account, epochTs, new bytes(0)).mulDiv(
            rewardsPerEpoch, $.activeSharesCache[epoch]
        );

        // Get the amount that is still unclaimed
        amount -= claimedPerEpoch;
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

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);
        // If the epoch is in the future, revert
        if (epochTs > Time.timestamp()) {
            revert ODefaultStakerRewards__InvalidRewardTimestamp();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        uint256 adminFee_ = $.adminFee;
        // If the admin fee is higher than the max allowed, revert
        if (maxAdminFee < adminFee_) {
            revert ODefaultStakerRewards__HighAdminFee();
        }

        // This is used to cache the active shares for the epoch and optimize the claiming process
        _cacheActiveShares($, epoch, epochTs, activeSharesHint, activeStakeHint);

        _transferAndCheckAmount(tokenAddress, amount);

        _updateAdminFeeAndRewards(amount, adminFee_, epoch, tokenAddress);

        emit DistributeRewards(i_network, tokenAddress, eraIndex, epoch, amount, data);
    }

    function _transferAndCheckAmount(address tokenAddress, uint256 amount) private {
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        uint256 finalAmount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

        // Check if the amount being sent is greater than 0
        if (finalAmount != amount) {
            revert ODefaultStakerRewards__InsufficientReward();
        }
    }

    function _cacheActiveShares(
        StakerRewardsStorage storage $,
        uint48 epoch,
        uint48 epochTs,
        bytes memory activeSharesHint,
        bytes memory activeStakeHint
    ) private {
        if ($.activeSharesCache[epoch] == 0) {
            uint256 activeShares_ = IVault(i_vault).activeSharesAt(epochTs, activeSharesHint);
            uint256 activeStake_ = IVault(i_vault).activeStakeAt(epochTs, activeStakeHint);

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

        if (distributeAmount != 0) {
            $.rewards[epoch][tokenAddress] += distributeAmount;
        }
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(
        address recipient,
        uint48 epoch,
        address tokenAddress,
        bytes calldata activeSharesOfHints
    ) public override nonReentrant {
        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        uint256 rewardsPerEpoch = $.rewards[epoch][tokenAddress];
        uint256 claimedPerEpoch = $.stakerClaimedRewardPerEpoch[recipient][epoch][tokenAddress];

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);

        uint256 activeSharesCache_ = $.activeSharesCache[epoch];

        if (rewardsPerEpoch == 0 || activeSharesCache_ == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }
        uint256 amount = IVault(i_vault).activeSharesOfAt(recipient, epochTs, activeSharesOfHints).mulDiv(
            rewardsPerEpoch, activeSharesCache_
        );

        // Get the amount that is still unclaimed
        amount -= claimedPerEpoch;

        // If there are no rewards to claim, revert
        if (amount == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        $.stakerClaimedRewardPerEpoch[recipient][epoch][tokenAddress] += amount;

        // if the amount is greater than 0, transfer the tokens to the recipient
        IERC20(tokenAddress).safeTransfer(recipient, amount);

        emit ClaimRewards(i_network, tokenAddress, msg.sender, epoch, recipient, amount);
    }

    /**
     * @dev Alternative method to claim rewards with custom data
     * @dev data = abi.encode(epoch, activeSharesOfHints)
     */
    function claimRewards(address recipient, address tokenAddress, bytes calldata data) external {
        uint48 epoch;
        assembly {
            epoch := calldataload(data.offset)
        }
        claimRewards(recipient, epoch, tokenAddress, data[0x20:]);
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

        emit ClaimAdminFee(recipient, tokenAddress, epoch, claimableAdminFee_);
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
     * @dev TODO: This function should be called only once and then should be upgraded to a new implementation without this function.
     */
    function setVault(
        address vault_
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (vault_ == address(0)) {
            revert ODefaultStakerRewards__InvalidAddress();
        }

        i_vault = vault_;

        emit SetVault(vault_);
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
    function rewards(uint48 epoch, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.rewards[epoch][tokenAddress];
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function stakerClaimedRewardPerEpoch(
        address account,
        uint48 epoch,
        address tokenAddress
    ) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.stakerClaimedRewardPerEpoch[account][epoch][tokenAddress];
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
        bytes32 position = STAKER_REWARDS_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }
}
