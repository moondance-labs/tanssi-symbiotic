// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ReceiverLogic - External library for receiver validation
/// @notice Extracts all pure/validation logic from IReceiverTemplate
library ReceiverLogic {
    error ReceiverLogic__InvalidAuthor(address received, address expected);
    error ReceiverLogic__InvalidWorkflowName(bytes10 received, bytes10 expected);
    error ReceiverLogic__InvalidWorkflowId(bytes32 received, bytes32 expected);

    /// @notice Validates metadata against expected values
    /// @dev External library call saves deployment size
    function validateMetadata(
        bytes calldata metadata,
        bytes32 expectedWorkflowId,
        address expectedAuthor,
        bytes10 expectedWorkflowName
    ) external pure {
        // Security Checks 2-4: Verify workflow identity - ID, owner, and/or name (if any are configured)
        if (expectedWorkflowId != bytes32(0) || expectedAuthor != address(0) || expectedWorkflowName != bytes10(0)) {
            (bytes32 workflowId, bytes10 workflowName, address workflowOwner) = _decodeMetadata(metadata);

            if (expectedWorkflowId != bytes32(0) && workflowId != expectedWorkflowId) {
                revert ReceiverLogic__InvalidWorkflowId(workflowId, expectedWorkflowId);
            }
            if (expectedAuthor != address(0) && workflowOwner != expectedAuthor) {
                revert ReceiverLogic__InvalidAuthor(workflowOwner, expectedAuthor);
            }
            if (expectedWorkflowName != bytes10(0) && workflowName != expectedWorkflowName) {
                revert ReceiverLogic__InvalidWorkflowName(workflowName, expectedWorkflowName);
            }
        }
    }

    /// @notice Converts workflow name string to bytes10
    function nameToBytes10(
        string calldata name
    ) external pure returns (bytes10) {
        if (bytes(name).length == 0) return bytes10(0);

        bytes32 hash = sha256(bytes(name));
        bytes memory hexString = _bytesToHexString(abi.encodePacked(hash));

        bytes10 result;
        assembly {
            result := mload(add(hexString, 32))
        }
        return result;
    }

    /// @notice Converts bytes to hex string
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

    /// @notice Decodes workflow metadata
    function _decodeMetadata(
        bytes memory metadata
    ) private pure returns (bytes32 workflowId, bytes10 workflowName, address workflowOwner) {
        assembly {
            workflowId := mload(add(metadata, 32))
            workflowName := mload(add(metadata, 64))
            workflowOwner := shr(mul(12, 8), mload(add(metadata, 74)))
        }
    }
}
