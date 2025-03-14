// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {BaseMiddleware} from "@symbiotic-middleware/middleware/BaseMiddleware.sol";
import {IOSharedVaults} from "src/interfaces/extensions/IOSharedVaults.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";

/**
 * @title OSharedVaults
 * @notice Contract for managing shared vaults that can be used by multiple operators
 * @dev Extends BaseMiddleware to provide access control for vault management functions
 */
abstract contract OSharedVaults is BaseMiddleware, IOSharedVaults {
    uint64 public constant SharedVaults_VERSION = 1;

    /**
     * @inheritdoc IOSharedVaults
     */
    function registerSharedVault(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) public checkAccess {
        // TODO Steven: check if sharedVault is a valid vault
        _beforeRegisterSharedVault(sharedVault, stakerRewardsParams);
        _registerSharedVault(sharedVault);
    }

    /**
     * @inheritdoc IOSharedVaults
     */
    function pauseSharedVault(
        address sharedVault
    ) public checkAccess {
        _beforePauseSharedVault(sharedVault);
        _pauseSharedVault(sharedVault);
    }

    /**
     * @inheritdoc IOSharedVaults
     */
    function unpauseSharedVault(
        address sharedVault
    ) public checkAccess {
        _beforeUnpauseSharedVault(sharedVault);
        _unpauseSharedVault(sharedVault);
    }

    /**
     * @inheritdoc IOSharedVaults
     */
    function unregisterSharedVault(
        address sharedVault
    ) public checkAccess {
        _beforeUnregisterSharedVault(sharedVault);
        _unregisterSharedVault(sharedVault);
    }

    /**
     * @notice Hook called before registering a shared vault
     * @param sharedVault The vault address
     * @param stakerRewardsParams Init params to create a staker rewards contract associated with the shared vault
     */
    function _beforeRegisterSharedVault(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) internal virtual {}

    /**
     * @notice Hook called before pausing a shared vault
     * @param sharedVault The vault address
     */
    function _beforePauseSharedVault(
        address sharedVault
    ) internal virtual {}

    /**
     * @notice Hook called before unpausing a shared vault
     * @param sharedVault The vault address
     */
    function _beforeUnpauseSharedVault(
        address sharedVault
    ) internal virtual {}

    /**
     * @notice Hook called before unregistering a shared vault
     * @param sharedVault The vault address
     */
    function _beforeUnregisterSharedVault(
        address sharedVault
    ) internal virtual {}
}
