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
import {ScaleCodec} from "@snowbridge/contracts/src/utils/ScaleCodec.sol";

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

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultOperatorRewards.v2
    struct OperatorRewardsStorage {
        uint48 operatorShare;
        mapping(uint48 eraIndex => EraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(bytes32 account => uint256 amount)) claimed;
        mapping(address vault => address stakerRewardsAddress) _UNUSED;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultOperatorRewards.v2")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant OPERATOR_REWARDS_STORAGE_LOCATION =
        0x9e763766bd4dc4b79493b61f657e7d458cf0270bbd21be73fbf773df86fbd400;

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
        _disableInitializers();
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

        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        $.operatorShare = operatorShare_;
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
    function batchClaimRewards(
        ClaimRewardsInput[] calldata inputs
    ) external nonReentrant returns (uint256 operatorAmount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        uint256 totalInputs = inputs.length;
        address tokenAddress;
        address operator;

        for (uint256 i; i < totalInputs;) {
            address currentOperator =
                IOBaseMiddlewareReader(middlewareAddress).operatorByKey(abi.encode(inputs[i].operatorKey));

            if (operator == address(0)) {
                operator = currentOperator;
            } else if (operator != currentOperator) {
                revert ODefaultOperatorRewards__BatchClaimSupportsASingleOperator();
            }

            (uint256 newOperatorAmount, address newTokenAddress) =
                _claimRewards(inputs[i], $, middlewareAddress, operator);

            if (tokenAddress == address(0)) {
                tokenAddress = newTokenAddress;
            } else if (tokenAddress != newTokenAddress) {
                revert ODefaultOperatorRewards__BatchClaimSupportsASingleToken();
            }

            operatorAmount += newOperatorAmount;

            unchecked {
                ++i;
            }
        }

        // We do a single transfer only at the end, to save gas
        IERC20(tokenAddress).safeTransfer(operator, operatorAmount);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        ClaimRewardsInput calldata input
    ) external nonReentrant returns (uint256 operatorAmount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        address tokenAddress;

        address operator = IOBaseMiddlewareReader(middlewareAddress).operatorByKey(abi.encode(input.operatorKey));

        (operatorAmount, tokenAddress) = _claimRewards(input, $, middlewareAddress, operator);

        // Transfer the operator rewards to the operator
        IERC20(tokenAddress).safeTransfer(operator, operatorAmount);
    }

    function _claimRewards(
        ClaimRewardsInput calldata input,
        OperatorRewardsStorage storage $,
        address middlewareAddress,
        address operator
    ) private returns (uint256 operatorAmount, address tokenAddress) {
        EraRoot memory eraRoot_ = $.eraRoot[input.eraIndex];
        tokenAddress = eraRoot_.tokenAddress;
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

        // Calculate the total amount of tokens that can be claimed which is:
        // total amount of tokens = (total points claimable * total amount) / total points
        operatorAmount = uint256(input.totalPointsClaimable).mulDiv(eraRoot_.amount, eraRoot_.totalPoints);

        uint48 eraIndex = input.eraIndex;
        // You can only claim everything and if it's claimed before revert
        if ($.claimed[eraIndex][input.operatorKey] != 0) {
            revert ODefaultOperatorRewards__AlreadyClaimed();
        }

        $.claimed[eraIndex][input.operatorKey] = operatorAmount;

        emit ClaimRewards(operator, tokenAddress, input.eraIndex, eraRoot_.epoch, msg.sender, operatorAmount);
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
    function claimed(uint48 eraIndex, bytes32 account) external view returns (uint256 amount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        amount = $.claimed[eraIndex][account];
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override checkAccess {}

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
