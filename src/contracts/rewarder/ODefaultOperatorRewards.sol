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

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultOperatorRewards.v2
    struct OperatorRewardsStorage {
        uint48 operatorShare;
        mapping(uint48 eraIndex => EraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(bytes32 account => uint256 amount)) claimed;
        mapping(address vault => address stakerRewardsAddress) vaultToStakerRewardsContract;
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultOperatorRewards.v2")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant OPERATOR_REWARDS_STORAGE_LOCATION =
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
        _setSelectorRole(this.setStakerRewardContract.selector, STAKER_REWARDS_SETTER_ROLE);

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
    ) external nonReentrant returns (uint256 amount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        uint256 totalInputs = inputs.length;
        for (uint256 i; i < totalInputs;) {
            amount += _claimRewards(inputs[i], $, middlewareAddress);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        ClaimRewardsInput calldata input
    ) external nonReentrant returns (uint256 amount) {
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        amount = _claimRewards(input, $, middlewareAddress);
    }

    function _claimRewards(
        ClaimRewardsInput calldata input,
        OperatorRewardsStorage storage $,
        address middlewareAddress
    ) private returns (uint256 amount) {
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

        _distributeRewardsForEachVault(epoch, eraIndex, tokenAddress, totalVaults, operatorVaults, amountPerVault, data);
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

        bytes32 operatorKey = input.operatorKey;
        // Starlight sends back only the operator key, thus we need to get back the operator address
        recipient = IOBaseMiddlewareReader(middlewareAddress).operatorByKey(abi.encode(operatorKey));

        uint48 eraIndex = input.eraIndex;
        // You can only claim everything and if it's claimed before revert
        if ($.claimed[eraIndex][operatorKey] != 0) {
            revert ODefaultOperatorRewards__AlreadyClaimed();
        }

        $.claimed[eraIndex][operatorKey] = amount;

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
            unchecked {
                totalPower += vaultPowers[i];
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

    function _distributeRewardsForEachVault(
        uint48 epoch,
        uint48 eraIndex,
        address tokenAddress,
        uint256 totalVaults,
        address[] memory operatorVaults,
        uint256[] memory amountPerVault,
        bytes calldata data
    ) private {
        (uint256 maxAdminFee, VaultHints[] memory hints) = abi.decode(data, (uint256, VaultHints[]));

        for (uint256 i; i < totalVaults;) {
            VaultHints memory vaultHints;
            // For backward compatibility, we allow empty hints array to mean no hints for any vault
            if (hints.length != 0) {
                vaultHints = hints[i];
            }
            _distributeRewardsForVault(
                operatorVaults[i], amountPerVault[i], vaultHints, epoch, eraIndex, tokenAddress, maxAdminFee
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
    function claimed(uint48 eraIndex, bytes32 account) external view returns (uint256 amount) {
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

    function _getOperatorRewardsStorage() private pure returns (OperatorRewardsStorage storage $) {
        bytes32 position = OPERATOR_REWARDS_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }

    function _distributeRewardsForVault(
        address vault,
        uint256 amount,
        VaultHints memory vaultHint,
        uint48 epoch,
        uint48 eraIndex,
        address tokenAddress,
        uint256 maxAdminFee
    ) private {
        if (amount != 0) {
            {
                OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
                address stakerRewardsForVault = $.vaultToStakerRewardsContract[vault];
                if (stakerRewardsForVault == address(0)) {
                    revert ODefaultOperatorRewards__StakerRewardsNotSetForVault(vault);
                }
                bytes memory stakerRewardsHints = _getStakerRewardsHints(vault, vaultHint, maxAdminFee);
                IERC20(tokenAddress).approve(stakerRewardsForVault, amount);
                IODefaultStakerRewards(stakerRewardsForVault).distributeRewards(
                    epoch, eraIndex, amount, tokenAddress, stakerRewardsHints
                );
            }
        }
    }

    function _getStakerRewardsHints(
        address vault,
        VaultHints memory vaultHint,
        uint256 maxAdminFee
    ) private pure returns (bytes memory) {
        if (vaultHint.vault == address(0)) {
            return abi.encode(maxAdminFee, new bytes(0), new bytes(0));
        }

        if (vaultHint.vault != vault) {
            revert ODefaultOperatorRewards__InvalidOrderForHintsPerVault();
        }

        return abi.encode(maxAdminFee, vaultHint.activeSharesHint, vaultHint.activeStakeHint);
    }

    function _checkNotZeroAddress(
        address address_
    ) private pure {
        if (address_ == address(0)) {
            revert ODefaultOperatorRewards__InvalidAddress();
        }
    }
}
