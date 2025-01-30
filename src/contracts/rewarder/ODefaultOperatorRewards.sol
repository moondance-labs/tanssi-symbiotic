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

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {SimpleKeyRegistry32} from "../libraries/SimpleKeyRegistry32.sol";

contract ODefaultOperatorRewards is ReentrancyGuard, IODefaultOperatorRewards {
    using SafeERC20 for IERC20;
    using Math for uint256;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_networkMiddlewareService;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_network;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    uint48 public s_operatorShare;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 eraIndex => EraRoot eraRoot) public s_eraRoot;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => uint48[] eraIndexes) public s_eraIndexesPerEpoch;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 eraIndex => mapping(address account => uint256 amount)) public s_claimed;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(address vault => address stakerRewardsAddress) public s_vaultToStakerRewardsContract;

    modifier onlyMiddleware() {
        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network) != msg.sender) {
            revert ODefaultOperatorRewards__NotNetworkMiddleware();
        }
        _;
    }

    constructor(address network, address networkMiddlewareService, address token, uint48 operatorShare) {
        i_network = network;
        i_networkMiddlewareService = networkMiddlewareService;
        s_operatorShare = operatorShare;
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

        // We need to calculate how much each point is worth in tokens
        uint256 tokensPerPoint = amount / totalPointsToken; // TODO: To change/check the math.

        EraRoot memory eraRoot = EraRoot({
            epoch: epoch,
            amount: amount,
            tokensPerPoint: tokensPerPoint,
            root: root,
            tokenAddress: tokenAddress
        });
        // We store the eraRoot struct which contains useful information for the claimRewards function and for UI
        // We store also the eraIndex in an array to be able to get all the eras for each epoch
        s_eraRoot[eraIndex] = eraRoot;
        s_eraIndexesPerEpoch[epoch].push(eraIndex);

        emit DistributeRewards(eraIndex, epoch, tokenAddress, tokensPerPoint, amount, root);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        ClaimRewardsInput calldata input
    ) external nonReentrant returns (uint256 amount) {
        EraRoot memory eraRoot = s_eraRoot[input.eraIndex];
        uint48 epoch = eraRoot.epoch;
        address tokenAddress = eraRoot.tokenAddress;
        if (eraRoot.root == bytes32(0)) {
            revert ODefaultOperatorRewards__RootNotSet();
        }

        // Check that the leaf composed by operatorKey and totalPointsClaimable is part of the proof
        if (
            !MerkleProof.verifyCalldata(
                input.proof,
                eraRoot.root,
                keccak256(abi.encodePacked(input.operatorKey, ScaleCodec.encodeU32(input.totalPointsClaimable)))
            )
        ) {
            revert ODefaultOperatorRewards__InvalidProof();
        }

        address middlewareAddress = INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network);
        // Starlight sends back only the operator key, thus we need to get back the operator address
        address recipient = SimpleKeyRegistry32(middlewareAddress).getOperatorByKey(input.operatorKey);

        // Calculate the total amount of tokens that can be claimed which is:
        // total amount of tokens = total points claimable * tokens per point
        amount = input.totalPointsClaimable * eraRoot.tokensPerPoint;

        // You can only claim everything and if it's claimed before revert
        if (s_claimed[input.eraIndex][recipient] > 0) {
            revert ODefaultOperatorRewards__InsufficientTotalClaimable();
        }

        s_claimed[input.eraIndex][recipient] = amount;

        // s_operatorShare% of the rewards to the operator
        uint256 operatorAmount = amount.mulDiv(s_operatorShare, 100);

        // (1-s_operatorShare)% of the rewards to the stakers
        uint256 stakerAmount = amount - operatorAmount;

        // On every claim send s_operatorShare% of the rewards to the operator
        // And then distribute rewards to the stakers
        // This is gonna send (1-s_operatorShare)% of the rewards
        IERC20(tokenAddress).safeTransfer(recipient, operatorAmount);

        _distributeRewardsToStakers(
            epoch, input.eraIndex, stakerAmount, recipient, middlewareAddress, tokenAddress, input.data
        );
        emit ClaimRewards(recipient, tokenAddress, input.eraIndex, epoch, msg.sender, amount);
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
        uint48 epochStartTs = IMiddleware(middlewareAddress).getEpochStartTs(epoch);

        //TODO: For now this is expected to be a single vault. Change it to be able to handle multiple vaults.
        (, address[] memory operatorVaults) = IMiddleware(middlewareAddress).getOperatorVaults(recipient, epochStartTs);

        // TODO: Currently it's only for a specific vault. We don't care now about making it able to send rewards for multiple vaults. It's hardcoded to the first vault of the operator.
        if (operatorVaults.length > 0) {
            IODefaultStakerRewards(s_vaultToStakerRewardsContract[operatorVaults[0]]).distributeRewards(
                epoch, eraIndex, stakerAmount, tokenAddress, data
            );
        }
    }

    //TODO Probably this function should become a function triggered by middleware that create a new staker contract (calling the create on factory contract) and then set the staker contract address here. Probably this can be called during registration of the vault? `registerVault`
    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function setStakerRewardContract(address stakerRewards, address vault) external onlyMiddleware {
        if (stakerRewards == address(0) || vault == address(0)) {
            revert ODefaultOperatorRewards__InvalidAddress();
        }

        if (s_vaultToStakerRewardsContract[vault] == stakerRewards) {
            revert ODefaultOperatorRewards__AlreadySet();
        }

        s_vaultToStakerRewardsContract[vault] = stakerRewards;

        emit SetStakerRewardContract(stakerRewards, vault);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function setOperatorShare(
        uint48 operatorShare
    ) external onlyMiddleware {
        //TODO A maximum value for the operatorShare should be chosen. 100% shouldn't be a valid option.
        if (operatorShare >= 100) {
            revert ODefaultOperatorRewards__InvalidOperatorShare();
        }
        if (operatorShare == s_operatorShare) {
            revert ODefaultOperatorRewards__AlreadySet();
        }

        s_operatorShare = operatorShare;

        emit SetOperatorShare(operatorShare);
    }
}
