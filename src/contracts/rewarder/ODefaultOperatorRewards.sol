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

import {IODefaultOperatorRewards} from "../../interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";

import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {SimpleKeyRegistry32} from "../libraries/SimpleKeyRegistry32.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ScaleCodec} from "@tanssi-bridge-relayer/snowbridge/contracts/src/utils/ScaleCodec.sol";

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
    address public immutable i_token;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable i_network;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public s_defaultStakerRewards;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    uint48 public s_operatorShare;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => bytes32 value) public s_epochRoot;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => BalancePerEpoch balancePerEpoch) public s_balance;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => mapping(address account => uint256 amount)) public s_claimed;

    modifier onlyMiddleware() {
        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network) != msg.sender) {
            revert ODefaultOperatorRewards__NotNetworkMiddleware();
        }
        _;
    }

    constructor(address network, address networkMiddlewareService, address token, uint48 operatorShare) {
        i_network = network;
        i_networkMiddlewareService = networkMiddlewareService;
        i_token = token;
        s_operatorShare = operatorShare;
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function distributeRewards(
        uint48 epoch,
        uint256 amount,
        uint256 totalPointsToken,
        bytes32 root
    ) external nonReentrant onlyMiddleware {
        if (amount > 0) {
            uint256 balanceBefore = IERC20(i_token).balanceOf(address(this));
            IERC20(i_token).safeTransferFrom(msg.sender, address(this), amount);
            amount = IERC20(i_token).balanceOf(address(this)) - balanceBefore;

            if (amount == 0) {
                revert ODefaultOperatorRewards__InsufficientTransfer();
            }

            if (totalPointsToken == 0) {
                revert ODefaultOperatorRewards__InvalidTotalPoints();
            }

            s_balance[epoch].amount = amount;
            s_balance[epoch].tokensPerPoint = amount / totalPointsToken; // TODO: To change the math.
        }

        s_epochRoot[epoch] = root;

        emit DistributeRewards(epoch, root);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        bytes32 operatorKey,
        uint48 epoch,
        uint32 totalPointsClaimable,
        bytes32[] calldata proof,
        bytes calldata data
    ) external nonReentrant returns (uint256 amount) {
        bytes32 root_ = s_epochRoot[epoch];
        if (root_ == bytes32(0)) {
            revert ODefaultOperatorRewards__RootNotSet();
        }

        if (
            !MerkleProof.verifyCalldata(
                proof, root_, keccak256(abi.encodePacked(operatorKey, ScaleCodec.encodeU32(totalPointsClaimable)))
            )
        ) {
            revert ODefaultOperatorRewards__InvalidProof();
        }

        address recipient = SimpleKeyRegistry32(
            INetworkMiddlewareService(i_networkMiddlewareService).middleware(i_network)
        ).getOperatorByKey(operatorKey);

        uint256 claimed_ = s_claimed[epoch][recipient]; //TODO: This can become a bool. uint256 it's better even UI wise as we would know exactly how much was claimed instead of querying 2 times the contract.

        amount = totalPointsClaimable * s_balance[epoch].tokensPerPoint * 10 ** 18; //! TODO Is it fine to use 10**18 here? We are saying that are all IERC20 with 18 decimals. What if we use USDC as collateral? Should we get the decimals for each token?

        if (amount <= claimed_) {
            revert ODefaultOperatorRewards__InsufficientTotalClaimable();
        }

        s_claimed[epoch][recipient] = amount;

        uint256 operatorAmount = amount.mulDiv(s_operatorShare, 100); // s_operatorShare% of the rewards to the operator
        uint256 stakerAmount = amount - operatorAmount; // (1-s_operatorShare)% of the rewards to the stakers

        // On every claim send s_operatorShare% of the rewards to the operator
        // And then distribute rewards to the stakers
        IERC20(i_token).safeTransfer(recipient, operatorAmount); //This is gonna send (1-s_operatorShare)% of the rewards
        IODefaultStakerRewards(s_defaultStakerRewards).distributeRewards(epoch, stakerAmount, data);
        emit ClaimRewards(recipient, epoch, msg.sender, amount);
    }

    function setStakerRewardContract(
        address stakerRewards
    ) external onlyMiddleware {
        s_defaultStakerRewards = stakerRewards;
    }

    function setOperatorShare(
        uint48 operatorShare
    ) external onlyMiddleware {
        //A maximum value for the operatorShare should be chosen. 100% shouldn't be a valid option.
        if (operatorShare >= 100) {
            revert ODefaultOperatorRewards__InvalidOperatorShare();
        }
        if (operatorShare == s_operatorShare) {
            revert ODefaultOperatorRewards__AlreadySet();
        }

        s_operatorShare = operatorShare;
    }
}
