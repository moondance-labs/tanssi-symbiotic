//SPDX-License-Identifier: GPL-3.0-or-later

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
pragma solidity ^0.8.0;

interface IMiddleware {
    /**
     * @notice Emitted when the interval for which the `performUpkeep` should be performed is set.
     * @param interval The interval in seconds
     */
    event IntervalSet(uint256 indexed interval);

    /**
     * @notice Emitted when the forwarder is set.
     * @param forwarder The forwarder address
     */
    event ForwarderSet(address indexed forwarder);

    // Errors
    error Middleware__GatewayNotSet();
    error Middleware__AlreadySet();
    error Middleware__AlreadyCached();
    error Middleware__TooOldEpoch();
    error Middleware__InvalidEpoch();
    error Middleware__InvalidCommand(uint8 command);
    error Middleware__InvalidEpochDuration();
    error Middleware__InvalidAddress();
    error Middleware__InvalidKey();
    error Middleware__InvalidInterval();
    error Middleware__NoPerformData();
    error Middleware__InsufficientBalance();
    error Middleware__SlashingWindowTooShort();
    error Middleware__SlashPercentageTooBig(uint48 epoch, address operator, uint256 percentage);
    error Middleware__TooManyActiveVaults();

    /**
     * @notice Validator data structure containing stake and key
     * @param power The validator's power, based on staked tokens and their price
     * @param key The validator's key
     */
    struct ValidatorData {
        uint256 power;
        bytes32 key;
    }

    /**
     * @notice Structure to pair an operator with their associated vaults
     * @param operator The operator's address
     * @param vaults Array of vault addresses associated with the operator
     */
    struct OperatorVaultPair {
        address operator;
        address[] vaults;
    }

    /**
     * @param network The network address
     * @param operatorRegistry The operator registry address
     * @param vaultRegistry The vault registry address
     * @param operatorNetOptin The operator network optin address
     * @param owner The owner address
     * @param epochDuration The epoch duration
     * @param slashingWindow The slashing window
     * @param reader The reader address
     */
    struct InitParams {
        address network;
        address operatorRegistry;
        address vaultRegistry;
        address operatorNetworkOptIn;
        address owner;
        uint48 epochDuration;
        uint48 slashingWindow;
        address reader;
    }

    /**
     * @notice Sets the interval on which to let Chainlink forwarder to call `performUpkeep`
     * @dev Only the owner can call this function
     * @param interval The interval
     */
    function setInterval(
        uint256 interval
    ) external;

    /**
     * @notice Sets the forwarder address
     * @param forwarder The forwarder address
     */
    function setForwarder(
        address forwarder
    ) external;

    /**
     * @notice Sets the operator share on operator rewards contract
     * @param operatorShare The operator share
     */
    function setOperatorShareOnOperatorRewards(
        uint48 operatorShare
    ) external;
}
