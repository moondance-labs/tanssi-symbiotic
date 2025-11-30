// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IReceiver} from "./IReceiver.sol";
import {OzAccessControl} from "@symbiotic-middleware/extensions/managers/access/OzAccessControl.sol";
import {MiddlewareStorage} from "src/contracts/middleware/MiddlewareStorage.sol";
import {console2} from "forge-std/console2.sol";

/// @title IReceiverTemplate - Abstract receiver with optional permission controls
/// @notice Provides flexible, updatable security checks for receiving workflow reports
/// @dev All permission fields default to zero (disabled). Use setter functions to enable checks.
abstract contract IReceiverTemplate is IReceiver, OzAccessControl, MiddlewareStorage {
    // Optional permission fields (all default to zero = disabled)

    /// @custom:storage-location erc7201:tanssi.middleware.IReceiverTemplate.v1
    struct ReceiverStorage {
        // TODO: Probably makes sense to move the forwarder here too?
        address expectedAuthor; // If set, only reports from this workflow owner are accepted
        bytes10 expectedWorkflowName; // If set, only reports with this workflow name are accepted
        bytes32 expectedWorkflowId; // If set, only reports from this specific workflow ID are accepted
    }

    // keccak256(abi.encode(uint256(keccak256("tanssi.middleware.IReceiverTemplate.v1")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 private constant RECEIVER_STORAGE_LOCATION =
        0x38cdda42a8f6f8aea435fed196af456308f802243734948617a51c08f50b8000;

    // Custom errors
    error IReceiverTemplate__InvalidAuthor(address received, address expected);
    error IReceiverTemplate__InvalidWorkflowName(bytes10 received, bytes10 expected);
    error IReceiverTemplate__InvalidWorkflowId(bytes32 received, bytes32 expected);

    /// @notice Constructor sets msg.sender as the owner
    /// @dev All permission fields are initialized to zero (disabled by default)
    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc IReceiver
    /// @dev Performs optional validation checks based on which permission fields are set
    function onReport(bytes calldata metadata, bytes calldata report) external override checkAccess {
        ReceiverStorage storage rs = _getReceiverStorage();
        address expectedAuthor = rs.expectedAuthor;
        bytes10 expectedWorkflowName = rs.expectedWorkflowName;
        bytes32 expectedWorkflowId = rs.expectedWorkflowId;

        // Security Checks 2-4: Verify workflow identity - ID, owner, and/or name (if any are configured)
        if (expectedWorkflowId != bytes32(0) || expectedAuthor != address(0) || expectedWorkflowName != bytes10(0)) {
            (bytes32 workflowId, bytes10 workflowName, address workflowOwner) = _decodeMetadata(metadata);

            if (expectedWorkflowId != bytes32(0) && workflowId != expectedWorkflowId) {
                revert IReceiverTemplate__InvalidWorkflowId(workflowId, expectedWorkflowId);
            }
            if (expectedAuthor != address(0) && workflowOwner != expectedAuthor) {
                revert IReceiverTemplate__InvalidAuthor(workflowOwner, expectedAuthor);
            }
            if (expectedWorkflowName != bytes10(0) && workflowName != expectedWorkflowName) {
                revert IReceiverTemplate__InvalidWorkflowName(workflowName, expectedWorkflowName);
            }
        }

        _processReport(report);
    }

    /// @notice Updates the expected workflow owner address
    /// @param _author The new expected author address (use address(0) to disable this check)
    function setExpectedAuthor(
        address _author
    ) external checkAccess {
        ReceiverStorage storage rs = _getReceiverStorage();
        rs.expectedAuthor = _author;
    }

    /// @notice Updates the expected workflow name from a plaintext string
    /// @param _name The workflow name as a string (use empty string "" to disable this check)
    /// @dev The name is hashed using SHA256 and truncated
    function setExpectedWorkflowName(
        string calldata _name
    ) external checkAccess {
        ReceiverStorage storage rs = _getReceiverStorage();
        if (bytes(_name).length == 0) {
            rs.expectedWorkflowName = bytes10(0);
            return;
        }

        // Convert workflow name to bytes10:
        // SHA256 hash → hex encode → take first 10 chars → hex encode those chars
        bytes32 hash = sha256(bytes(_name));
        bytes memory hexString = _bytesToHexString(abi.encodePacked(hash));
        bytes memory first10 = new bytes(10);
        for (uint256 i = 0; i < 10; i++) {
            first10[i] = hexString[i];
        }
        rs.expectedWorkflowName = bytes10(first10);
    }

    /// @notice Updates the expected workflow ID
    /// @param _id The new expected workflow ID (use bytes32(0) to disable this check)
    function setExpectedWorkflowId(
        bytes32 _id
    ) external checkAccess {
        ReceiverStorage storage rs = _getReceiverStorage();
        rs.expectedWorkflowId = _id;
    }

    /// @notice Helper function to convert bytes to hex string
    /// @param data The bytes to convert
    /// @return The hex string representation
    function _bytesToHexString(
        bytes memory data
    ) private pure returns (bytes memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory hexString = new bytes(data.length * 2);

        for (uint256 i = 0; i < data.length; i++) {
            hexString[i * 2] = hexChars[uint8(data[i] >> 4)];
            hexString[i * 2 + 1] = hexChars[uint8(data[i] & 0x0f)];
        }

        return hexString;
    }

    /// @notice Extracts all metadata fields from the onReport metadata parameter
    /// @param metadata The metadata in bytes format
    /// @return workflowId The unique identifier of the workflow (bytes32)
    /// @return workflowName The name of the workflow (bytes10)
    /// @return workflowOwner The owner address of the workflow
    function _decodeMetadata(
        bytes memory metadata
    ) internal pure returns (bytes32 workflowId, bytes10 workflowName, address workflowOwner) {
        // Metadata structure:
        // - First 32 bytes: length of the byte array (standard for dynamic bytes)
        // - Offset 32, size 32: workflow_id (bytes32)
        // - Offset 64, size 10: workflow_name (bytes10)
        // - Offset 74, size 20: workflow_owner (address)
        assembly {
            workflowId := mload(add(metadata, 32))
            workflowName := mload(add(metadata, 64))
            workflowOwner := shr(mul(12, 8), mload(add(metadata, 74)))
        }
    }

    /// @notice Abstract function to process the report data
    /// @param report The report calldata containing your workflow's encoded data
    /// @dev Implement this function with your contract's business logic
    function _processReport(
        bytes calldata report
    ) internal virtual;

    function _getReceiverStorage() internal pure returns (ReceiverStorage storage rs) {
        assembly {
            rs.slot := RECEIVER_STORAGE_LOCATION
        }
    }

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 interfaceId
    ) public pure virtual override returns (bool) {
        return interfaceId == type(IReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
