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

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

import {Middleware} from "src/contracts/middleware/Middleware.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

contract ODefaultOperatorRewards is
    OwnableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    IODefaultOperatorRewards
{
    using SafeERC20 for IERC20;
    using Math for uint256;

    // keccak256(abi.encode(uint256(keccak256("tanssi.rewards.ODefaultOperatorRewards.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MAIN_STORAGE_LOCATION = 0x57cf781f364664df22ab0472e35114435fb4a6881ab5a1b47ed6d1a7d4605400;

    /// @custom:storage-location erc7201:tanssi.rewards.ODefaultOperatorRewards.v1
    struct OperatorRewardsStorage {
        uint48 operatorShare;
        mapping(uint48 eraIndex => EraRoot eraRoot) eraRoot;
        mapping(uint48 epoch => uint48[] eraIndexes) eraIndexesPerEpoch;
        mapping(uint48 eraIndex => mapping(address account => uint256 amount)) claimed;
        mapping(address vault => address stakerRewardsAddress) vaultToStakerRewardsContract;
    }

    uint48 public constant MAX_PERCENTAGE = 10_000;
    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_network;

    modifier onlyMiddleware() {
        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network) != msg.sender) {
            revert ODefaultOperatorRewards__NotNetworkMiddleware();
        }
        _;
    }

    constructor(address network, address networkMiddlewareService) {
        i_network = network;
        i_networkMiddlewareService = networkMiddlewareService;
    }

    function initialize(uint48 operatorShare_, address owner_) public initializer {
        __Ownable_init(owner_);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
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
        uint256 totalPointsToken,
        bytes32 root,
        address tokenAddress
    ) external nonReentrant onlyMiddleware {
        if (amount > 0) {
            // Check if the amount being sent is greater than 0
            uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
            IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
            amount = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

            if (amount == 0) {
                revert ODefaultOperatorRewards__InsufficientTransfer();
            }

            if (totalPointsToken == 0) {
                revert ODefaultOperatorRewards__InvalidTotalPoints();
            }
        }

        EraRoot memory eraRoot_ = EraRoot({
            epoch: epoch,
            amount: amount,
            // We need to calculate how much each point is worth in tokens
            tokensPerPoint: amount / totalPointsToken, // TODO: To change/check the math.
            root: root,
            tokenAddress: tokenAddress
        });
        // We store the eraRoot struct which contains useful information for the claimRewards function and for UI
        // We store also the eraIndex in an array to be able to get all the eras for each epoch
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        $.eraRoot[eraIndex] = eraRoot_;
        $.eraIndexesPerEpoch[epoch].push(eraIndex);

        emit DistributeRewards(epoch, eraIndex, tokenAddress, eraRoot_.tokensPerPoint, amount, root);
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
        // Starlight sends back only the operator key, thus we need to get back the operator address
        address recipient = Middleware(middlewareAddress).operatorByKey(abi.encode(input.operatorKey));

        // Calculate the total amount of tokens that can be claimed which is:
        // total amount of tokens = total points claimable * tokens per point
        amount = input.totalPointsClaimable * eraRoot_.tokensPerPoint;

        // You can only claim everything and if it's claimed before revert
        if ($.claimed[input.eraIndex][recipient] > 0) {
            revert ODefaultOperatorRewards__InsufficientTotalClaimable();
        }

        $.claimed[input.eraIndex][recipient] = amount;

        // operatorShare% of the rewards to the operator
        uint256 operatorAmount = amount.mulDiv($.operatorShare, MAX_PERCENTAGE);

        // (1-s_operatorShare)% of the rewards to the stakers
        uint256 stakerAmount = amount - operatorAmount;

        // On every claim send operatorShare% of the rewards to the operator
        // And then distribute rewards to the stakers
        // This is gonna send (1-s_operatorShare)% of the rewards
        IERC20(tokenAddress).safeTransfer(recipient, operatorAmount);

        _distributeRewardsToStakers(
            eraRoot_.epoch, input.eraIndex, stakerAmount, recipient, middlewareAddress, tokenAddress, input.data
        );
        emit ClaimRewards(recipient, tokenAddress, input.eraIndex, eraRoot_.epoch, msg.sender, amount);
    }

    function _distributeRewardsToStakers(
        uint48 epoch,
        uint48 eraIndex,
        uint256 stakerAmount,
        address recipient,
        address middlewareAddress,
        address tokenAddress,
        bytes calldata data
    ) private {
        uint48 epochStartTs = EpochCapture(middlewareAddress).getEpochStart(epoch);

        //TODO: For now this is expected to be a single vault. Change it to be able to handle multiple vaults.
        (, address[] memory operatorVaults) = Middleware(middlewareAddress).getOperatorVaults(recipient, epochStartTs);

        // TODO: Currently it's only for a specific vault. We don't care now about making it able to send rewards for multiple vaults. It's hardcoded to the first vault of the operator.
        OperatorRewardsStorage storage $ = _getOperatorRewardsStorage();
        if (operatorVaults.length > 0) {
            IODefaultStakerRewards($.vaultToStakerRewardsContract[operatorVaults[0]]).distributeRewards(
                epoch, eraIndex, stakerAmount, tokenAddress, data
            );
        }
    }

    //TODO Probably this function should become a function triggered by middleware that create a new staker contract (calling the create on factory contract) and then set the staker contract address here. Probably this can be called during registration of the vault? `registerSharedVault`
    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function setStakerRewardContract(address stakerRewards, address vault) external onlyMiddleware {
        if (stakerRewards == address(0) || vault == address(0)) {
            revert ODefaultOperatorRewards__InvalidAddress();
        }
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
    ) external onlyMiddleware {
        //TODO A maximum value for the operatorShare should be chosen. 100% shouldn't be a valid option.
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
    function claimed(uint48 eraIndex, address account) external view returns (uint256 amount) {
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
    ) internal override onlyOwner {}

    function _getOperatorRewardsStorage() private pure returns (OperatorRewardsStorage storage $) {
        bytes32 position = MAIN_STORAGE_LOCATION;
        assembly {
            $.slot := position
        }
    }
}
