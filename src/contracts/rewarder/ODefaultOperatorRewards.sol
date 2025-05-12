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

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************

import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {OzAccessControl} from "@symbiotic-middleware/extensions/managers/access/OzAccessControl.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

contract ODefaultOperatorRewards is
    OzAccessControl,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IODefaultOperatorRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;
    using Subnetwork for address;
    using Subnetwork for bytes32;

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultOperatorRewards.v1
    struct OldOperatorRewardsStorage {
        uint48 operatorShare;
        mapping(uint48 eraIndex => OldEraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(address account => uint256 amount)) claimed;
        mapping(address vault => address stakerRewardsAddress) vaultToStakerRewardsContract;
    }

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultOperatorRewards.v2
    struct OperatorRewardsStorage {
        uint48 operatorShare;
        mapping(uint48 eraIndex => EraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(bytes account => uint256 amount)) claimed; // Todo shall we use bytes or bytes32 for account?
        mapping(address vault => address stakerRewardsAddress) vaultToStakerRewardsContract;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultOperatorRewards.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant OLD_OPERATOR_REWARDS_STORAGE_LOCATION =
        0x57cf781f364664df22ab0472e35114435fb4a6881ab5a1b47ed6d1a7d4605400;

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultOperatorRewards.v2")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant OPERATOR_REWARDS_STORAGE_LOCATION =
        0x9e763766bd4dc4b79493b61f657e7d458cf0270bbd21be73fbf773df86fbd400;

    bytes32 public constant STAKER_REWARDS_SETTER_ROLE = keccak256("STAKER_REWARDS_SETTER_ROLE");
    bytes32 public constant MIDDLEWARE_ROLE = keccak256("MIDDLEWARE_ROLE");
    uint48 public constant MAX_PERCENTAGE = 10_000;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_network;

    modifier notZeroAddress(
        address address_
    ) {
        _checkNotZeroAddress(address_);
        _;
    }

    constructor(
        address network,
        address networkMiddlewareService
    ) notZeroAddress(network) notZeroAddress(networkMiddlewareService) {
        i_network = network;
        i_networkMiddlewareService = networkMiddlewareService;
    }

    /**
     * @notice Initialize the contract.
     * @param operatorShare_ The share of the operator.
     * @param owner The address of the owner.
     */
    function initialize(uint48 operatorShare_, address owner) external initializer notZeroAddress(owner) {
        if (operatorShare_ >= MAX_PERCENTAGE) {
            revert ODefaultOperatorRewards__InvalidOperatorShare();
        }

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __OzAccessControl_init(owner);

        _grantRole(DEFAULT_ADMIN_ROLE, owner);

        _setSelectorRole(this.distributeRewards.selector, MIDDLEWARE_ROLE);
        _setSelectorRole(this.setOperatorShare.selector, MIDDLEWARE_ROLE);
        _setSelectorRole(this.setStakerRewardContract.selector, STAKER_REWARDS_SETTER_ROLE);

        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        $.operatorShare = operatorShare_;
    }

    function migrate(uint48 startEpoch, uint48 endEpoch) external checkAccess {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        OldOperatorRewardsStorage storage $old = _getOldOperatorRewardsStorage();
        address middleware = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        IOBaseMiddlewareReader reader = IOBaseMiddlewareReader(middleware);

        for (uint48 epoch = startEpoch; epoch <= endEpoch;) {
            uint48[] memory eraIndexes = $old.eraIndexesPerEpoch[epoch];
            uint48 epochTs = EpochCapture(middleware).getEpochStart(epoch);
            address[] memory operators = reader.activeOperatorsAt(epochTs);
            _migrateVaultsToStakerRewards($, $old, operators, epochTs, reader);

            for (uint48 eraIndex; eraIndex < eraIndexes.length; eraIndex++) {
                if ($.eraIndexesPerEpoch[epoch].length > 0) {
                    continue; // TODO: It already migrated, shall it revert instead?
                }
                uint48 eraIndex_ = eraIndexes[eraIndex];
                OldEraRoot memory oldEraRoot_ = $old.eraRoot[eraIndex_];

                EraRoot memory newEraRoot = EraRoot({
                    epoch: epoch,
                    amount: oldEraRoot_.amount,
                    totalPoints: oldEraRoot_.amount * oldEraRoot_.tokensPerPoint,
                    root: oldEraRoot_.root,
                    tokenAddress: oldEraRoot_.tokenAddress
                });
                $.eraRoot[eraIndex] = newEraRoot;
                $.eraIndexesPerEpoch[epoch].push(eraIndex);
                _migrateClaimed($, $old, eraIndex, operators, reader);
            }
            unchecked {
                ++epoch;
            }
        }
    }

    function _migrateClaimed(
        OperatorRewardsStorage storage $,
        OldOperatorRewardsStorage storage $old,
        uint48 eraIndex,
        address[] memory operators,
        IOBaseMiddlewareReader reader
    ) private {
        for (uint48 i; i < operators.length;) {
            address operator = operators[i];
            bytes memory operatorKey = reader.operatorKey(operator);
            uint256 claimedAmount = $old.claimed[eraIndex][operator];
            if (claimedAmount == 0) {
                continue;
            }
            if ($.claimed[eraIndex][operatorKey] != 0) {
                continue; // TODO: It already migrated, shall it revert instead?
            }
            $.claimed[eraIndex][operatorKey] = claimedAmount;

            unchecked {
                ++i;
            }
        }
    }

    function _migrateVaultsToStakerRewards(
        OperatorRewardsStorage storage $,
        OldOperatorRewardsStorage storage $old,
        address[] memory operators,
        uint48 epochTs,
        IOBaseMiddlewareReader reader
    ) private {
        for (uint48 i; i < operators.length;) {
            address operator = operators[i];
            (, address[] memory operatorVaults) = reader.getOperatorVaults(operator, epochTs);
            for (uint48 j; j < operatorVaults.length;) {
                address vault = operatorVaults[j];
                if ($.vaultToStakerRewardsContract[vault] != address(0)) {
                    continue; // Already migrated
                }
                $.vaultToStakerRewardsContract[vault] = $old.vaultToStakerRewardsContract[vault];

                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function distributeRewards(
        uint48 epoch,
        uint48 eraIndex,
        uint256 amount,
        uint256 totalPoints,
        bytes32 root,
        address tokenAddress
    ) external nonReentrant checkAccess {
        if (amount == 0 || totalPoints == 0) {
            revert ODefaultOperatorRewards__InvalidValues();
        }

        // Check if the amount being sent is greater than 0
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        uint256 transferredAmount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

        if (transferredAmount != amount) {
            revert ODefaultOperatorRewards__InsufficientTransfer();
        }

        EraRoot memory eraRoot_ = EraRoot({
            epoch: epoch,
            amount: amount,
            // We need to calculate how much each point is worth in tokens
            totalPoints: totalPoints,
            root: root,
            tokenAddress: tokenAddress
        });
        // We store the eraRoot struct which contains useful information for the claimRewards function and for UI
        // We store also the eraIndex in an array to be able to get all the eras for each epoch
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        $.eraRoot[eraIndex] = eraRoot_;
        $.eraIndexesPerEpoch[epoch].push(eraIndex);

        emit DistributeRewards(epoch, eraIndex, tokenAddress, totalPoints, amount, root);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        ClaimRewardsInput calldata input
    ) external nonReentrant returns (uint256 amount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        EraRoot memory eraRoot_ = $.eraRoot[input.eraIndex];
        address tokenAddress = eraRoot_.tokenAddress;
        if (eraRoot_.root == bytes32(0)) {
            revert ODefaultOperatorRewards__RootNotSet();
        }

        // Check that the leaf composed by operatorKey and totalPointsClaimable is part of the proof
        if (
            !MerkleProof.verifyCalldata(
                input.proof,
                eraRoot_.root,
                keccak256(abi.encodePacked(input.operatorKey, ScaleCodec.encodeU32(input.totalPointsClaimable)))
            )
        ) {
            revert ODefaultOperatorRewards__InvalidProof();
        }

        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        uint256 stakerAmount;
        address recipient;

        (amount, stakerAmount, recipient) = _distributeRewardsToOperator($, input, eraRoot_, middlewareAddress);

        _distributeRewardsToStakers(
            eraRoot_.epoch, input.eraIndex, stakerAmount, recipient, middlewareAddress, tokenAddress, input.data
        );
        emit ClaimRewards(recipient, tokenAddress, input.eraIndex, eraRoot_.epoch, msg.sender, amount);
    }

    function _distributeRewardsToStakers(
        uint48 epoch,
        uint48 eraIndex,
        uint256 stakerAmount,
        address operator,
        address middlewareAddress,
        address tokenAddress,
        bytes calldata data
    ) private {
        uint48 epochStartTs = EpochCapture(middlewareAddress).getEpochStart(epoch);

        (, address[] memory operatorVaults) =
            IOBaseMiddlewareReader(middlewareAddress).getOperatorVaults(operator, epochStartTs);

        uint256 totalVaults = operatorVaults.length;
        if (totalVaults == 0) {
            revert ODefaultOperatorRewards__NoVaults();
        }
        uint256[] memory amountPerVault = _getRewardsAmountPerVault(
            operatorVaults, totalVaults, epochStartTs, operator, middlewareAddress, stakerAmount
        );

        _distributeRewardsPerVault(epoch, eraIndex, tokenAddress, totalVaults, operatorVaults, amountPerVault, data);
    }

    function _distributeRewardsToOperator(
        OperatorRewardsStorage storage $,
        ClaimRewardsInput calldata input,
        EraRoot memory eraRoot_,
        address middlewareAddress
    ) private returns (uint256 amount, uint256 stakerAmount, address recipient) {
        // Calculate the total amount of tokens that can be claimed which is:
        // total amount of tokens = (total points claimable * total amount) / total points
        amount = uint256(input.totalPointsClaimable).mulDiv(eraRoot_.amount, eraRoot_.totalPoints);

        bytes memory operatorKey = abi.encode(input.operatorKey);
        // Starlight sends back only the operator key, thus we need to get back the operator address
        recipient = IOBaseMiddlewareReader(middlewareAddress).operatorByKey(operatorKey);

        // You can only claim everything and if it's claimed before revert
        if ($.claimed[input.eraIndex][operatorKey] != 0) {
            revert ODefaultOperatorRewards__InsufficientTotalClaimable();
        }

        $.claimed[input.eraIndex][operatorKey] = amount;

        // operatorShare% of the rewards to the operator
        uint256 operatorAmount = amount.mulDiv($.operatorShare, MAX_PERCENTAGE);

        // (1-s_operatorShare)% of the rewards to the stakers
        stakerAmount = amount - operatorAmount;

        // On every claim send operatorShare% of the rewards to the operator
        // And then distribute rewards to the stakers
        // This is gonna send (1-s_operatorShare)% of the rewards
        IERC20(eraRoot_.tokenAddress).safeTransfer(recipient, operatorAmount);
    }

    function _getRewardsAmountPerVault(
        address[] memory operatorVaults,
        uint256 totalVaults,
        uint48 epochStartTs,
        address operator,
        address middlewareAddress,
        uint256 stakerAmount
    ) private view returns (uint256[] memory amountPerVault) {
        // First we get the operator power per vault
        uint96 subnetwork = i_network.subnetwork(0).identifier();
        IOBaseMiddlewareReader reader = IOBaseMiddlewareReader(middlewareAddress);

        uint256[] memory vaultPowers = new uint256[](totalVaults);
        uint256 totalPower;
        for (uint256 i; i < totalVaults;) {
            vaultPowers[i] = reader.getOperatorPowerAt(epochStartTs, operator, operatorVaults[i], subnetwork);
            totalPower += vaultPowers[i];
            unchecked {
                ++i;
            }
        }

        // Then we calculate the rewards according to the operator power on each vault
        uint256 distributedAmount;
        amountPerVault = new uint256[](totalVaults);
        for (uint256 i; i < totalVaults;) {
            uint256 amountForVault;
            // Last vault gets the remaining amount
            if (i == totalVaults - 1) {
                amountForVault = stakerAmount - distributedAmount;
            } else {
                amountForVault = vaultPowers[i].mulDiv(stakerAmount, totalPower);
            }
            amountPerVault[i] = amountForVault;
            unchecked {
                distributedAmount += amountForVault;
                ++i;
            }
        }
    }

    function _distributeRewardsPerVault(
        uint48 epoch,
        uint48 eraIndex,
        address tokenAddress,
        uint256 totalVaults,
        address[] memory operatorVaults,
        uint256[] memory amountPerVault,
        bytes calldata data
    ) private {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        for (uint256 i; i < totalVaults;) {
            address stakerRewardsForVault = $.vaultToStakerRewardsContract[operatorVaults[i]];
            IERC20(tokenAddress).approve(stakerRewardsForVault, amountPerVault[i]);
            IODefaultStakerRewards(stakerRewardsForVault).distributeRewards(
                epoch, eraIndex, amountPerVault[i], tokenAddress, data
            );

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function setStakerRewardContract(
        address stakerRewards,
        address vault
    ) external checkAccess notZeroAddress(stakerRewards) notZeroAddress(vault) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();

        if ($.vaultToStakerRewardsContract[vault] == stakerRewards) {
            revert ODefaultOperatorRewards__AlreadySet();
        }

        $.vaultToStakerRewardsContract[vault] = stakerRewards;

        emit SetStakerRewardContract(stakerRewards, vault);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function setOperatorShare(
        uint48 operatorShare_
    ) external checkAccess {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        if (operatorShare_ >= MAX_PERCENTAGE) {
            revert ODefaultOperatorRewards__InvalidOperatorShare();
        }
        if (operatorShare_ == $.operatorShare) {
            revert ODefaultOperatorRewards__AlreadySet();
        }

        $.operatorShare = operatorShare_;

        emit SetOperatorShare(operatorShare_);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function operatorShare() external view returns (uint48 operatorShare_) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        operatorShare_ = $.operatorShare;
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function eraRoot(
        uint48 eraIndex
    ) external view returns (EraRoot memory eraRoot_) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        eraRoot_ = $.eraRoot[eraIndex];
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function eraIndexesPerEpoch(uint48 epoch, uint256 index) external view returns (uint48 eraIndex) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        eraIndex = $.eraIndexesPerEpoch[epoch][index];
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimed(uint48 eraIndex, bytes memory account) external view returns (uint256 amount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        amount = $.claimed[eraIndex][account];
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function vaultToStakerRewardsContract(
        address vault
    ) external view returns (address stakerRewards) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        stakerRewards = $.vaultToStakerRewardsContract[vault];
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override checkAccess {}

    function _getOldOperatorRewardsStorage() private pure returns (OldOperatorRewardsStorage storage $) {
        bytes32 position = OLD_OPERATOR_REWARDS_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }

    function _getOperatorRewardsStorage() private pure returns (OperatorRewardsStorage storage $) {
        bytes32 position = OPERATOR_REWARDS_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }

    function _checkNotZeroAddress(
        address address_
    ) private pure {
        if (address_ == address(0)) {
            revert ODefaultOperatorRewards__InvalidAddress();
        }
    }
}
