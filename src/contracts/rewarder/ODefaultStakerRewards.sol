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

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IMiddlewareStorage} from "src/interfaces/middleware/IMiddlewareStorage.sol";
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";

contract ODefaultStakerRewards is
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    MulticallUpgradeable,
    IODefaultStakerRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultStakerRewards.v1.2
    struct StakerRewardsStorage {
        uint256 adminFee;
        mapping(uint48 epoch => mapping(address vault => mapping(address tokenAddress => uint256 rewards_))) rewards;
        mapping(
            address account
                => mapping(uint48 epoch => mapping(address vault => mapping(address tokenAddress => uint256 claimed)))
        ) stakerClaimedRewardPerEpoch;
        mapping(uint48 epoch => mapping(address tokenAddress => uint256) amount) claimableAdminFee;
        mapping(uint48 epoch => mapping(address vault => uint256 amount)) activeSharesCache;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultStakerRewards.v1.2")) - 1)) & ~bytes32(uint256(0xff))
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
    bytes32 public constant MIDDLEWARE_ROLE = keccak256("MIDDLEWARE_ROLE");
    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    address public immutable i_network;

    constructor(address networkMiddlewareService, address network) {
        _disableInitializers();

        if (network == address(0) || networkMiddlewareService == address(0)) {
            revert ODefaultStakerRewards__InvalidAddress();
        }
        i_networkMiddlewareService = networkMiddlewareService;
        i_network = network;
    }

    function initialize(address middleware, InitParams calldata params) external initializer {
        if (middleware == address(0)) {
            revert ODefaultStakerRewards__InvalidAddress();
        }

        if (params.defaultAdminRoleHolder == address(0)) {
            revert ODefaultStakerRewards__MissingRoles();
        }

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _setAdminFee(params.adminFee);

        _grantRole(DEFAULT_ADMIN_ROLE, params.defaultAdminRoleHolder);
        if (params.adminFeeClaimRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_CLAIM_ROLE, params.adminFeeClaimRoleHolder);
        }
        if (params.adminFeeSetRoleHolder != address(0)) {
            _grantRole(ADMIN_FEE_SET_ROLE, params.adminFeeSetRoleHolder);
        }
        _grantRole(MIDDLEWARE_ROLE, middleware);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimable(
        uint48 epoch,
        address account,
        address vault,
        address tokenAddress
    ) external view returns (uint256 amount) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();

        if ($.activeSharesCache[epoch][vault] == 0) {
            return 0;
        }

        uint256 rewardsPerEpoch = $.rewards[epoch][vault][tokenAddress];
        uint256 claimedPerEpoch = $.stakerClaimedRewardPerEpoch[account][epoch][vault][tokenAddress];

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);

        amount = IVault(vault).activeSharesOfAt(account, epochTs, new bytes(0)).mulDiv(
            rewardsPerEpoch, $.activeSharesCache[epoch][vault]
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
    ) external override nonReentrant onlyRole(MIDDLEWARE_ROLE) {
        // maxAdminFee - the maximum admin fee to allow
        (uint256 maxAdminFee) = abi.decode(data, (uint256));

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);
        // If the epoch is in the future, revert
        if (epochTs > Time.timestamp()) {
            revert ODefaultStakerRewards__InvalidRewardTimestamp();
        }

        _setFeeAndSetRewards(maxAdminFee, epoch, amount, tokenAddress);

        _transferAndCheckAmount(tokenAddress, amount);

        emit DistributeRewards(i_network, tokenAddress, eraIndex, epoch, amount, data);
    }

    function _setFeeAndSetRewards(uint256 maxAdminFee, uint48 epoch, uint256 amount, address tokenAddress) private {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256 adminFee_ = $.adminFee;
        // If the admin fee is higher than the max allowed, revert
        if (maxAdminFee < adminFee_) {
            revert ODefaultStakerRewards__HighAdminFee();
        }

        // Take out the admin fee from the rewards
        uint256 adminFeeAmount = amount.mulDiv(adminFee_, ADMIN_FEE_BASE);
        // And distribute the rest to the stakers
        uint256 distributeAmount = amount - adminFeeAmount;

        $.claimableAdminFee[epoch][tokenAddress] += adminFeeAmount;

        if (distributeAmount != 0) {
            _setRewardsPerVault($, distributeAmount, epoch, tokenAddress);
        }
    }

    function _setRewardsPerVault(
        StakerRewardsStorage storage $,
        uint256 amount,
        uint48 epoch,
        address tokenAddress
    ) private {
        address middleware = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);

        address[] memory activeVaults = IOBaseMiddlewareReader(middleware).activeVaults();
        uint256 totalVaultPower = IMiddlewareStorage(middleware).getEpochTotalPower(epoch);
        console2.log("Total vault power:", totalVaultPower);
        uint256 cumulativeAmount;
        for (uint256 i; i < activeVaults.length;) {
            address vault = activeVaults[i];
            uint256 vaultPower = IMiddlewareStorage(middleware).getVaultToPowerCached(epoch, vault);
            console2.log("Vault power: ", vaultPower);
            uint256 rewardsPerVault;
            if (i == activeVaults.length - 1) {
                rewardsPerVault = amount - cumulativeAmount;
            } else {
                rewardsPerVault = amount.mulDiv(vaultPower, totalVaultPower);
            }
            console2.log("Rewards for vault: ", rewardsPerVault);
            $.rewards[epoch][vault][tokenAddress] = rewardsPerVault;

            unchecked {
                cumulativeAmount += rewardsPerVault;
                ++i;
            }
        }
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

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(
        address recipient,
        uint48 epoch,
        address tokenAddress,
        address vault,
        bytes calldata activeSharesOfHints
    ) public nonReentrant {
        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256 amount = _claimRewards(recipient, epoch, tokenAddress, vault, activeSharesOfHints, $);

        IERC20(tokenAddress).safeTransfer(recipient, amount);

        uint48[] memory epochs = new uint48[](1);
        epochs[0] = epoch;
        emit ClaimRewards(i_network, tokenAddress, msg.sender, epochs, recipient, amount);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimRewards(address recipient, address tokenAddress, bytes calldata data) external {
        uint48 epoch;
        address vault;
        assembly {
            epoch := calldataload(data.offset)
            vault := calldataload(add(data.offset, 0x20))
        }
        claimRewards(recipient, epoch, tokenAddress, vault, data[0x40:]);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function batchClaimRewards(
        address recipient,
        uint48[] calldata epochs,
        address tokenAddress,
        address vault,
        bytes[] calldata activeSharesOfHints
    ) external {
        batchClaimRewardsAndRestake(recipient, epochs, tokenAddress, vault, activeSharesOfHints, 0);
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function batchClaimRewardsAndRestake(
        address recipient,
        uint48[] calldata epochs,
        address tokenAddress,
        address vault,
        bytes[] calldata activeSharesOfHints,
        uint48 restakePercentageBps
    ) public {
        uint256 totalAmount = _batchClaimRewards(recipient, epochs, tokenAddress, vault, activeSharesOfHints);

        uint256 restakeAmount = totalAmount.mulDiv(restakePercentageBps, 10_000);
        uint256 claimAmount = totalAmount - restakeAmount;

        if (claimAmount != 0) {
            IERC20(tokenAddress).safeTransfer(recipient, claimAmount);
        }

        if (restakeAmount != 0) {
            if (IVault(vault).collateral() != tokenAddress) {
                revert ODefaultStakerRewards__RewardsTokenIsDifferentFromCollateral();
            }
            IERC20(tokenAddress).approve(vault, restakeAmount);
            IVault(vault).deposit(recipient, restakeAmount);
        }
    }

    function _batchClaimRewards(
        address recipient,
        uint48[] calldata epochs,
        address tokenAddress,
        address vault,
        bytes[] calldata activeSharesOfHints
    ) private returns (uint256 totalAmount) {
        if (recipient == address(0)) {
            revert ODefaultStakerRewards__InvalidRecipient();
        }
        if (epochs.length != activeSharesOfHints.length) {
            revert ODefaultStakerRewards__InvalidInput();
        }

        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        uint256 epochsLength = epochs.length;
        for (uint256 i; i < epochsLength;) {
            uint256 amount = _claimRewards(recipient, epochs[i], tokenAddress, vault, activeSharesOfHints[i], $);
            totalAmount += amount;
            unchecked {
                ++i;
            }
        }

        emit ClaimRewards(i_network, tokenAddress, msg.sender, epochs, recipient, totalAmount);
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
     * @inheritdoc IODefaultStakerRewards
     */
    function adminFee() external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.adminFee;
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function rewards(uint48 epoch, address vault, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.rewards[epoch][vault][tokenAddress];
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function stakerClaimedRewardPerEpoch(
        address account,
        uint48 epoch,
        address vault,
        address tokenAddress
    ) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.stakerClaimedRewardPerEpoch[account][epoch][vault][tokenAddress];
    }

    /**
     * @inheritdoc IODefaultStakerRewards
     */
    function claimableAdminFee(uint48 epoch, address tokenAddress) external view returns (uint256) {
        StakerRewardsStorage storage $ = _getStakerRewardsStorage();
        return $.claimableAdminFee[epoch][tokenAddress];
    }

    function _claimRewards(
        address recipient,
        uint48 epoch,
        address tokenAddress,
        address vault,
        bytes memory activeSharesOfHints,
        StakerRewardsStorage storage $
    ) private returns (uint256 amount) {
        uint256 rewardsPerEpoch = $.rewards[epoch][vault][tokenAddress];
        uint256 claimedPerEpoch = $.stakerClaimedRewardPerEpoch[recipient][epoch][vault][tokenAddress];

        uint48 epochTs = EpochCapture(INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network))
            .getEpochStart(epoch);

        uint256 activeSharesCache_ = $.activeSharesCache[epoch][vault];
        if (activeSharesCache_ == 0) {
            uint256 activeShares_ = IVault(vault).activeSharesAt(epochTs, activeSharesOfHints);
            uint256 activeStake_ = IVault(vault).activeStakeAt(epochTs, new bytes(0));

            if (activeShares_ == 0 || activeStake_ == 0) {
                revert ODefaultStakerRewards__InvalidRewardTimestamp();
            }

            $.activeSharesCache[epoch][vault] = activeShares_;
            activeSharesCache_ = activeShares_;
        }

        if (rewardsPerEpoch == 0 || activeSharesCache_ == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        amount = IVault(vault).activeSharesOfAt(recipient, epochTs, activeSharesOfHints).mulDiv(
            rewardsPerEpoch, activeSharesCache_
        );

        // Get the amount that is still unclaimed
        amount -= claimedPerEpoch;

        // If there are no rewards to claim, revert
        if (amount == 0) {
            revert ODefaultStakerRewards__NoRewardsToClaim();
        }

        $.stakerClaimedRewardPerEpoch[recipient][epoch][vault][tokenAddress] += amount;
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
