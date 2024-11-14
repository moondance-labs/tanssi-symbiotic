// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {console2} from "forge-std/console2.sol";

import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Checkpoints} from "@symbiotic/contracts/libraries/Checkpoints.sol";

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

contract OptInServiceMock is EIP712, IOptInService {
    using Checkpoints for Checkpoints.Trace208;

    address public immutable WHO_REGISTRY;
    address public immutable WHERE_REGISTRY;

    mapping(address who => mapping(address where => uint256 nonce)) public nonces;

    mapping(address who => mapping(address where => Checkpoints.Trace208 value)) internal _isOptedIn;

    constructor(address whoRegistry, address whereRegistry, string memory name) EIP712(name, "1") {
        WHO_REGISTRY = whoRegistry;
        WHERE_REGISTRY = whereRegistry;
    }

    function isOptedInAt(
        address who,
        address where,
        uint48 timestamp,
        bytes calldata hint
    ) external view returns (bool) {
        return _isOptedIn[who][where].upperLookupRecent(timestamp, hint) == 1;
    }

    function isOptedIn(address who, address where) public view returns (bool) {
        return _isOptedIn[who][where].latest() == 1;
    }

    function optIn(
        address where
    ) external {
        _optIn(msg.sender, where);
    }

    function optIn(address who, address where, uint48 deadline, bytes calldata signature) external {
        _optIn(who, where);
    }

    function optOut(
        address where
    ) external {
        _optOut(msg.sender, where);
    }

    function optOut(address who, address where, uint48 deadline, bytes calldata signature) external {
        _optOut(who, where);
    }

    function increaseNonce(
        address where
    ) external {
        _increaseNonce(msg.sender, where);
    }

    function _optIn(address who, address where) internal {
        _isOptedIn[who][where].push(Time.timestamp(), 1);

        _increaseNonce(who, where);

        emit OptIn(who, where);
    }

    function _optOut(address who, address where) internal {
        _isOptedIn[who][where].push(Time.timestamp(), 0);

        _increaseNonce(who, where);

        emit OptOut(who, where);
    }

    function _increaseNonce(address who, address where) internal {
        unchecked {
            ++nonces[who][where];
        }

        emit IncreaseNonce(who, where);
    }
}
