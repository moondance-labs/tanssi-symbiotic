// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IReceiver} from "./IReceiver.sol";
import {OzAccessControl} from "@symbiotic-middleware/extensions/managers/access/OzAccessControl.sol";
import {ReceiverLogic} from "src/contracts/libraries/ReceiverLogic.sol";

/// @title IReceiverTemplate - Abstract receiver with optional permission controls
/// @notice Provides flexible, updatable security checks for receiving workflow reports
/// @dev All permission fields default to zero (disabled). Use setter functions to enable checks.
abstract contract IReceiverTemplate is IReceiver, OzAccessControl {
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

    /// @notice Constructor sets msg.sender as the owner
    /// @dev All permission fields are initialized to zero (disabled by default)
    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc IReceiver
    /// @dev Performs optional validation checks based on which permission fields are set
    function onReport(bytes calldata metadata, bytes calldata report) external override checkAccess {
        ReceiverStorage storage rs = _getReceiverStorage();

        // Delegate validation to external library
        ReceiverLogic.validateMetadata(metadata, rs.expectedWorkflowId, rs.expectedAuthor, rs.expectedWorkflowName);

        _processReport(report);
    }

    /// @notice Updates the expected workflow owner address
    /// @param _author The new expected author address (use address(0) to disable this check)
    function setExpectedAuthor(
        address _author
    ) external checkAccess {
        _getReceiverStorage().expectedAuthor = _author;
    }

    /// @notice Updates the expected workflow name from a plaintext string
    /// @param _name The workflow name as a string (use empty string "" to disable this check)
    /// @dev The name is hashed using SHA256 and truncated
    function setExpectedWorkflowName(
        string calldata _name
    ) external checkAccess {
        _getReceiverStorage().expectedWorkflowName = ReceiverLogic.nameToBytes10(_name);
    }

    /// @notice Updates the expected workflow ID
    /// @param _id The new expected workflow ID (use bytes32(0) to disable this check)
    function setExpectedWorkflowId(
        bytes32 _id
    ) external checkAccess {
        _getReceiverStorage().expectedWorkflowId = _id;
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
