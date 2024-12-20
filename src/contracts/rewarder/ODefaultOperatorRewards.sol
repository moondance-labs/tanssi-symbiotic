// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IODefaultOperatorRewards} from "../../interfaces/rewarder/IODefaultOperatorRewards.sol";

import {INetworkMiddlewareService} from "@symbioticfi/core/src/interfaces/service/INetworkMiddlewareService.sol";

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract DefaultOperatorRewards is ReentrancyGuardUpgradeable, IODefaultOperatorRewards {
    using SafeERC20 for IERC20;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    address public immutable NETWORK_MIDDLEWARE_SERVICE;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    // ! this should have the epoch and let's see if we need the token or we know we are just gonna use tanssi token
    mapping(address network => mapping(address token => bytes32 value)) public root;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    // ! this should have the epoch
    mapping(address network => mapping(address token => uint256 amount)) public balance;

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    mapping(address network => mapping(address token => mapping(address account => uint256 amount))) public claimed;

    constructor(
        address networkMiddlewareService
    ) {
        //! Probably we won't need this
        _disableInitializers();

        NETWORK_MIDDLEWARE_SERVICE = networkMiddlewareService;
    }

    function initialize() public initializer {
        __ReentrancyGuard_init();
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function distributeRewards(address network, address token, uint256 amount, bytes32 root_) external nonReentrant {
        if (INetworkMiddlewareService(NETWORK_MIDDLEWARE_SERVICE).middleware(network) != msg.sender) {
            revert NotNetworkMiddleware();
        }

        if (amount > 0) {
            uint256 balanceBefore = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            amount = IERC20(token).balanceOf(address(this)) - balanceBefore;

            if (amount == 0) {
                revert InsufficientTransfer();
            }

            balance[network][token] += amount;
        }

        root[network][token] = root_;

        emit DistributeRewards(network, token, amount, root_);
    }

    /**
     * @inheritdoc IODefaultOperatorRewards
     */
    function claimRewards(
        address recipient,
        address network,
        address token,
        uint256 totalClaimable,
        bytes32[] calldata proof
    ) external nonReentrant returns (uint256 amount) {
        bytes32 root_ = root[network][token];
        if (root_ == bytes32(0)) {
            revert RootNotSet();
        }

        if (
            !MerkleProof.verifyCalldata(
                proof, root_, keccak256(bytes.concat(keccak256(abi.encode(msg.sender, totalClaimable))))
            )
        ) {
            revert InvalidProof();
        }

        uint256 claimed_ = claimed[network][token][msg.sender];
        if (totalClaimable <= claimed_) {
            revert InsufficientTotalClaimable();
        }

        amount = totalClaimable - claimed_;

        uint256 balance_ = balance[network][token];
        if (amount > balance_) {
            revert InsufficientBalance();
        }

        balance[network][token] = balance_ - amount;

        claimed[network][token][msg.sender] = totalClaimable;

        IERC20(token).safeTransfer(recipient, amount);

        emit ClaimRewards(recipient, network, token, msg.sender, amount);
    }
}
