// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IODefaultOperatorRewards} from "../../interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewards} from "../../interfaces/rewarder/IODefaultStakerRewards.sol";

import {INetworkMiddlewareService} from "@symbiotic/interfaces/service/INetworkMiddlewareService.sol";
import {SimpleKeyRegistry32} from "../libraries/SimpleKeyRegistry32.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ScaleCodec} from "@snowbridge/src/utils/ScaleCodec.sol";

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

    address public s_defaultStakerRewards;

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

    constructor(address network, address networkMiddlewareService, address token) {
        i_network = network;
        i_networkMiddlewareService = networkMiddlewareService;
        i_token = token;
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

            s_balance[epoch].amount = amount;
            s_balance[epoch].tokensPerPoint = amount / totalPointsToken; // To change the math. Check it's not zero
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

        // This should be double checked
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

        uint256 claimed_ = s_claimed[epoch][recipient]; // this can beecome a bool.
        if (totalPointsClaimable <= claimed_) {
            revert ODefaultOperatorRewards__InsufficientTotalClaimable();
        }

        amount = totalPointsClaimable - claimed_;

        //TODO Recheck this part
        uint256 balance_ = s_balance[epoch].amount;
        if (amount > balance_) {
            revert ODefaultOperatorRewards__InsufficientBalance();
        }

        amount = totalPointsClaimable * s_balance[epoch].tokensPerPoint;
        s_claimed[epoch][recipient] = amount;

        //!Comment 1: Math here is important. Please double check if this is what we want!!
        uint256 operatorAmount = amount.mulDiv(20, 100); // 20% of the rewards to the operator
        uint256 stakerAmount = amount - operatorAmount; // 80% of the rewards to the stakers

        // On every claim send 20% of the rewards to the operator
        // And then distribute rewards to the stakers
        IERC20(i_token).safeTransfer(recipient, operatorAmount); //This is gonna send 20% of the rewards
        IODefaultStakerRewards(s_defaultStakerRewards).distributeRewards(epoch, stakerAmount, data);
        emit ClaimRewards(recipient, epoch, msg.sender, amount);
    }

    function setStakerRewardContract(
        address stakerRewards
    ) external onlyMiddleware {
        s_defaultStakerRewards = stakerRewards;
    }
}
