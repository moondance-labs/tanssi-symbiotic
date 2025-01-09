// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IODefaultOperatorRewards} from "../../interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";

import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

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

    // Do we want this immutable? Or can we upgrade it?
    address public s_network;

    address public s_defaultStakerRewards;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => bytes32 value) public s_epochRoot;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => uint256 amount) public s_balance;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(uint48 epoch => mapping(address account => uint256 amount)) public s_claimed;

    constructor(address networkMiddlewareService, address token) {
        i_networkMiddlewareService = networkMiddlewareService;
        i_token = token;
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function distributeRewards(uint48 epoch, uint256 amount, bytes32 root) external nonReentrant {
        if (INetworkMiddlewareService(i_networkMiddlewareService).middleware(s_network) != msg.sender) {
            revert NotNetworkMiddleware();
        }

        if (amount > 0) {
            uint256 balanceBefore = IERC20(i_token).balanceOf(address(this));
            IERC20(i_token).safeTransferFrom(msg.sender, address(this), amount);
            amount = IERC20(i_token).balanceOf(address(this)) - balanceBefore;

            if (amount == 0) {
                revert InsufficientTransfer();
            }

            s_balance[epoch] += amount;
        }

        s_epochRoot[epoch] = root;

        emit DistributeRewards(epoch, root);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        address recipient,
        uint48 epoch,
        bytes32[] calldata proof,
        bytes calldata data
    ) external nonReentrant returns (uint256 amount) {
        bytes32 root_ = s_epochRoot[epoch];
        if (root_ == bytes32(0)) {
            revert RootNotSet();
        }

        if (!MerkleProof.verifyCalldata(proof, root_, keccak256(bytes.concat(keccak256(abi.encode(msg.sender)))))) {
            revert InvalidProof();
        }

        uint256 claimed_ = s_claimed[epoch][msg.sender];
        uint256 totalClaimable = s_balance[epoch];

        if (totalClaimable <= claimed_) {
            revert InsufficientTotalClaimable();
        }

        amount = totalClaimable - claimed_;

        uint256 balance_ = s_balance[epoch];
        if (amount > balance_) {
            revert InsufficientBalance();
        }

        s_balance[epoch] = balance_ - amount;

        s_claimed[epoch][msg.sender] = amount;

        //!Comment 1: Math here is important. Please double check if this is what we want!!
        uint256 operatorAmount = amount.mulDiv(20, 100); // 20% of the rewards to the operator
        uint256 stakerAmount = amount - operatorAmount; // 80% of the rewards to the stakers

        // On every claim send 20% of the rewards to the operator
        // And then distribute rewards to the stakers
        IERC20(i_token).safeTransfer(recipient, operatorAmount); //This is gonna send 20% of the rewards
        IODefaultStakerRewards(s_defaultStakerRewards).distributeRewards(epoch, stakerAmount, data);

        emit ClaimRewards(recipient, epoch, msg.sender, amount);
    }
}
