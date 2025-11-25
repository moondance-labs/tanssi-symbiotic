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
pragma solidity 0.8.25;

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {OBaseMiddlewareReader} from "src/contracts/middleware/OBaseMiddlewareReader.sol";

/**
 * @title OBaseMiddlewareReaderForwarder
 * @notice This will run all the calls to the OBaseMiddlewareReader using the middleware address passed in the constructor
 * @dev This allows anyone to read information using etherscan.
 */
contract OBaseMiddlewareReaderForwarder {
    IOBaseMiddlewareReader public middleware;

    constructor(
        address middleware_
    ) {
        middleware = IOBaseMiddlewareReader(middleware_);
    }

    function stakeToPower(address vault, uint256 stake) public view returns (uint256 power) {
        return middleware.stakeToPower(vault, stake);
    }

    /**
     * @notice Converts stake amount to voting power in USD
     * @param vault The vault address
     * @param stake The stake amount
     * @return power The calculated voting power (equal to stake)
     */
    function getPowerInUSD(address vault, uint256 stake) public view returns (uint256 power) {
        return middleware.getPowerInUSD(vault, stake);
    }

    /**
     * @notice Gets the network address
     * @return The network address
     */
    function NETWORK() external view returns (address) {
        return middleware.NETWORK();
    }

    /**
     * @notice Gets the slashing window
     * @return The slashing window
     */
    function SLASHING_WINDOW() external view returns (uint48) {
        return middleware.SLASHING_WINDOW();
    }

    /**
     * @notice Gets the vault registry address
     * @return The vault registry address
     */
    function VAULT_REGISTRY() external view returns (address) {
        return middleware.VAULT_REGISTRY();
    }

    /**
     * @notice Gets the operator registry address
     * @return The operator registry address
     */
    function OPERATOR_REGISTRY() external view returns (address) {
        return middleware.OPERATOR_REGISTRY();
    }

    /**
     * @notice Gets the operator net opt-in address
     * @return The operator net opt-in address
     */
    function OPERATOR_NET_OPTIN() external view returns (address) {
        return middleware.OPERATOR_NET_OPTIN();
    }

    /**
     * @notice Gets the number of operators
     * @return The number of operators
     */
    function operatorsLength() external view returns (uint256) {
        return middleware.operatorsLength();
    }

    /**
     * @notice Gets the operator and its times at a specific position
     * @param pos The position
     * @return The operator address, start time, and end time
     */
    function operatorWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48) {
        return middleware.operatorWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active operators
     * @return The list of active operators
     */
    function activeOperators() external view returns (address[] memory) {
        return middleware.activeOperators();
    }

    /**
     * @notice Gets the list of active operators at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active operators at the given timestamp
     */
    function activeOperatorsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return middleware.activeOperatorsAt(timestamp);
    }

    /**
     * @notice Checks if an operator was active at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return True if the operator was active at the given timestamp, false otherwise
     */
    function operatorWasActiveAt(uint48 timestamp, address operator) external view returns (bool) {
        return middleware.operatorWasActiveAt(timestamp, operator);
    }

    /**
     * @notice Checks if an operator is registered
     * @param operator The operator address
     * @return True if the operator is registered, false otherwise
     */
    function isOperatorRegistered(
        address operator
    ) external view returns (bool) {
        return middleware.isOperatorRegistered(operator);
    }

    /**
     * @notice Gets the number of subnetworks
     * @return The number of subnetworks
     */
    function subnetworksLength() external view returns (uint256) {
        return middleware.subnetworksLength();
    }

    /**
     * @notice Gets the subnetwork and its times at a specific position
     * @param pos The position
     * @return The subnetwork address, start time, and end time
     */
    function subnetworkWithTimesAt(
        uint256 pos
    ) external view returns (uint160, uint48, uint48) {
        return middleware.subnetworkWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active subnetworks
     * @return The list of active subnetworks
     */
    function activeSubnetworks() external view returns (uint160[] memory) {
        return middleware.activeSubnetworks();
    }

    /**
     * @notice Gets the list of active subnetworks at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active subnetworks at the given timestamp
     */
    function activeSubnetworksAt(
        uint48 timestamp
    ) external view returns (uint160[] memory) {
        return middleware.activeSubnetworksAt(timestamp);
    }

    /**
     * @notice Checks if a subnetwork was active at a specific timestamp
     * @param timestamp The timestamp
     * @param subnetwork The subnetwork address
     * @return True if the subnetwork was active at the given timestamp, false otherwise
     */
    function subnetworkWasActiveAt(uint48 timestamp, uint96 subnetwork) external view returns (bool) {
        return middleware.subnetworkWasActiveAt(timestamp, subnetwork);
    }

    /**
     * @notice Gets the number of shared vaults
     * @return The number of shared vaults
     */
    function sharedVaultsLength() external view returns (uint256) {
        return middleware.sharedVaultsLength();
    }

    /**
     * @notice Gets the shared vault and its times at a specific position
     * @param pos The position
     * @return The shared vault address, start time, and end time
     */
    function sharedVaultWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48) {
        return middleware.sharedVaultWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active shared vaults
     * @return The list of active shared vaults
     */
    function activeSharedVaults() external view returns (address[] memory) {
        return middleware.activeSharedVaults();
    }

    /**
     * @notice Gets the list of active shared vaults at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active shared vaults at the given timestamp
     */
    function activeSharedVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return middleware.activeSharedVaultsAt(timestamp);
    }

    /**
     * @notice Gets the number of vaults for a specific operator
     * @param operator The operator address
     * @return The number of vaults for the given operator
     */
    function operatorVaultsLength(
        address operator
    ) external view returns (uint256) {
        return middleware.operatorVaultsLength(operator);
    }

    /**
     * @notice Gets the operator vault and its times at a specific position
     * @param operator The operator address
     * @param pos The position
     * @return The operator vault address, start time, and end time
     */
    function operatorVaultWithTimesAt(address operator, uint256 pos) external view returns (address, uint48, uint48) {
        return middleware.operatorVaultWithTimesAt(operator, pos);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator
     * @param operator The operator address
     * @return The list of active vaults for the given operator
     */
    function activeOperatorVaults(
        address operator
    ) external view returns (address[] memory) {
        return middleware.activeOperatorVaults(operator);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The list of active vaults for the given operator at the given timestamp
     */
    function activeOperatorVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory) {
        return middleware.activeOperatorVaultsAt(timestamp, operator);
    }

    /**
     * @notice Gets the list of active vaults
     * @return The list of active vaults
     */
    function activeVaults() external view returns (address[] memory) {
        return middleware.activeVaults();
    }

    /**
     * @notice Gets the list of active vaults at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active vaults at the given timestamp
     */
    function activeVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return middleware.activeVaultsAt(timestamp);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator
     * @param operator The operator address
     * @return The list of active vaults for the given operator
     */
    function activeVaults(
        address operator
    ) external view returns (address[] memory) {
        return middleware.activeVaults(operator);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The list of active vaults for the given operator at the given timestamp
     */
    function activeVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory) {
        return middleware.activeVaultsAt(timestamp, operator);
    }

    /**
     * @notice Checks if a vault was active at a specific timestamp for a specific operator
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vault The vault address
     * @return True if the vault was active at the given timestamp for the given operator, false otherwise
     */
    function vaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool) {
        return middleware.vaultWasActiveAt(timestamp, operator, vault);
    }

    /**
     * @notice Checks if a shared vault was active at a specific timestamp
     * @param timestamp The timestamp
     * @param vault The shared vault address
     * @return True if the shared vault was active at the given timestamp, false otherwise
     */
    function sharedVaultWasActiveAt(uint48 timestamp, address vault) external view returns (bool) {
        return middleware.sharedVaultWasActiveAt(timestamp, vault);
    }

    /**
     * @notice Checks if an operator vault was active at a specific timestamp for a specific operator
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vault The vault address
     * @return True if the operator vault was active at the given timestamp for the given operator, false otherwise
     */
    function operatorVaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool) {
        return middleware.operatorVaultWasActiveAt(timestamp, operator, vault);
    }

    /**
     * @notice Gets the power of an operator for a specific vault and subnetwork
     * @param operator The operator address
     * @param vault The vault address
     * @param subnetwork The subnetwork address
     * @return The power of the operator for the given vault and subnetwork
     */
    function getOperatorPower(address operator, address vault, uint96 subnetwork) external view returns (uint256) {
        return middleware.getOperatorPower(operator, vault, subnetwork);
    }

    /**
     * @notice Gets the power of an operator for a specific vault and subnetwork at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vault The vault address
     * @param subnetwork The subnetwork address
     * @return The power of the operator for the given vault and subnetwork at the given timestamp
     */
    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address vault,
        uint96 subnetwork
    ) external view returns (uint256) {
        return middleware.getOperatorPowerAt(timestamp, operator, vault, subnetwork);
    }

    /**
     * @notice Gets the power of an operator
     * @param operator The operator address
     * @return The power of the operator
     */
    function getOperatorPower(
        address operator
    ) external view returns (uint256) {
        return middleware.getOperatorPower(operator);
    }

    /**
     * @notice Gets the power of an operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The power of the operator at the given timestamp
     */
    function getOperatorPowerAt(uint48 timestamp, address operator) external view returns (uint256) {
        return middleware.getOperatorPowerAt(timestamp, operator);
    }

    /**
     * @notice Gets the power of an operator for specific vaults and subnetworks
     * @param operator The operator address
     * @param vaults The list of vault addresses
     * @param subnetworks The list of subnetwork addresses
     * @return The power of the operator for the given vaults and subnetworks
     */
    function getOperatorPower(
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256) {
        return middleware.getOperatorPower(operator, vaults, subnetworks);
    }

    /**
     * @notice Gets the power of an operator for specific vaults and subnetworks at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vaults The list of vault addresses
     * @param subnetworks The list of subnetwork addresses
     * @return The power of the operator for the given vaults and subnetworks at the given timestamp
     */
    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256) {
        return middleware.getOperatorPowerAt(timestamp, operator, vaults, subnetworks);
    }

    /**
     * @notice Gets the total power of a list of operators
     * @param operators The list of operator addresses
     * @return The total power of the given operators
     */
    function totalPower(
        address[] memory operators
    ) external view returns (uint256) {
        return middleware.totalPower(operators);
    }

    /**
     * @notice Gets how many operators were active at a specific epoch
     * @param epoch The epoch at which to check how many operators were active
     * @return activeOperators_ The array of active operators
     */
    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory activeOperators_) {
        uint48 epochStartTs = middleware.getEpochStart(epoch);
        activeOperators_ = middleware.activeOperatorsAt(epochStartTs);
    }

    /**
     * @notice Gets operator-vault pairs for an epoch
     * @param epoch The epoch number
     * @return operatorVaultPairs Array of operator-vault pairs
     */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (IMiddleware.OperatorVaultPair[] memory operatorVaultPairs) {
        return middleware.getOperatorVaultPairs(epoch);
    }

    function getOperatorsForVault(uint48 epoch, address vault) external view returns (address[] memory operators) {
        IMiddleware.OperatorVaultPair[] memory operatorVaultPairs = middleware.getOperatorVaultPairs(epoch);
        operators = new address[](operatorVaultPairs.length);
        uint256 foundOperators;

        for (uint256 i; i < operatorVaultPairs.length;) {
            IMiddleware.OperatorVaultPair memory operatorVaultPair = operatorVaultPairs[i];
            uint256 vaultsLength = operatorVaultPair.vaults.length;
            for (uint256 j; j < vaultsLength;) {
                if (operatorVaultPair.vaults[j] == vault) {
                    operators[foundOperators++] = operatorVaultPair.operator;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
        assembly {
            mstore(operators, foundOperators)
        }
    }

    /**
     * @notice Checks if a vault is registered
     * @param vault The vault address to check
     * @return bool True if vault is registered
     */
    function isVaultRegistered(
        address vault
    ) external view returns (bool) {
        return middleware.isVaultRegistered(vault);
    }

    /**
     * @dev Sorts operators by their total power in descending order, after 500 it will be almost impossible to be used on-chain since 500 ≈ 36M gas
     * @param epoch The epoch number
     * @return sortedKeys Array of sorted operators keys based on their power
     */
    function sortOperatorsByPower(
        uint48 epoch
    ) public view returns (bytes32[] memory sortedKeys) {
        return middleware.sortOperatorsByPower(epoch);
    }

    /**
     * @notice Gets operator-vault pairs for an operator
     * @param operator the operator address
     * @param epochStartTs the epoch start timestamp
     * @return vaultIdx the index of the vault
     * @return vaults the array of vaults
     */
    function getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) public view returns (uint256 vaultIdx, address[] memory vaults) {
        return middleware.getOperatorVaults(operator, epochStartTs);
    }

    /**
     * @notice Gets total stake for an epoch
     * @param epoch The epoch number
     * @return totalStake Total stake amount
     */
    function getTotalStake(
        uint48 epoch
    ) external view returns (uint256 totalStake) {
        return middleware.getTotalStake(epoch);
    }

    /**
     * @notice Gets an operator's active key at the current capture timestamp
     * @param operator The operator address to lookup
     * @return The operator's active key encoded as bytes, or encoded zero bytes if none
     */
    function getOperatorKeyAt(address operator, uint48 timestamp) public view returns (bytes memory) {
        return middleware.getOperatorKeyAt(operator, timestamp);
    }

    /**
     * @notice Gets validator set for an epoch
     * @param epoch The epoch number
     * @return validatorSet validatorsData Array of validator data
     */
    function getValidatorSet(
        uint48 epoch
    ) public view returns (IMiddleware.ValidatorData[] memory validatorSet) {
        return middleware.getValidatorSet(epoch);
    }

    /**
     * @notice Determines which epoch a timestamp belongs to
     * @param timestamp The timestamp to check
     * @return epoch The corresponding epoch number
     */
    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48 epoch) {
        return middleware.getEpochAtTs(timestamp);
    }

    /**
     * @notice Returns the capture timestamp for the current epoch
     * @return timestamp The capture timestamp
     */
    function getCaptureTimestamp() external view returns (uint48 timestamp) {
        return middleware.getCaptureTimestamp();
    }

    /**
     * @notice Returns the current epoch number
     * @return The current epoch
     */
    function getCurrentEpoch() external view returns (uint48) {
        return middleware.getCurrentEpoch();
    }

    /**
     * @notice Returns the duration of each epoch
     * @return The duration of each epoch
     */
    function getEpochDuration() external view returns (uint48) {
        return middleware.getEpochDuration();
    }

    /**
     * @notice Returns the start timestamp for a given epoch
     * @param epoch The epoch number
     * @return The start timestamp
     */
    function getEpochStart(
        uint48 epoch
    ) external view returns (uint48) {
        return middleware.getEpochStart(epoch);
    }

    /**
     * @notice Checks if a key was active at a specific timestamp
     * @param timestamp The timestamp
     * @param key The key to check
     * @return True if the key was active at the given timestamp, false otherwise
     */
    function keyWasActiveAt(uint48 timestamp, bytes memory key) external view returns (bool) {
        return middleware.keyWasActiveAt(timestamp, key);
    }

    /**
     * @notice Gets the operator key for a given operator
     * @param operator The operator address
     * @return The operator key encoded as bytes
     */
    function operatorKey(
        address operator
    ) external view returns (bytes memory) {
        return middleware.operatorKey(operator);
    }

    /**
     * @notice Gets the operator address for a given key
     * @param key The operator key
     * @return The operator address
     */
    function operatorByKey(
        bytes memory key
    ) external view returns (address) {
        return middleware.operatorByKey(key);
    }

    /**
     * @notice Get the oracle address for a collateral
     * @param collateral The collateral address
     * @return The oracle address
     */
    function collateralToOracle(
        address collateral
    ) external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).collateralToOracle(collateral);
    }

    /**
     * @notice Get the collateral address for a vault
     * @param vault The vault address
     * @return The collateral address
     */
    function vaultToCollateral(
        address vault
    ) external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).vaultToCollateral(vault);
    }

    /**
     * @notice Get the oracle address for a vault
     * @param vault The vault address
     * @return The oracle address
     */
    function vaultToOracle(
        address vault
    ) external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).vaultToOracle(vault);
    }

    /**
     * @notice Get epoch operators cache index
     * @param epoch The epoch number
     * @return The index of the cache for the epoch or how many operators have had their powers cached
     */
    function getEpochCacheIndex(
        uint48 epoch
    ) external view returns (uint256) {
        return OBaseMiddlewareReader(address(middleware)).getEpochCacheIndex(epoch);
    }

    /**
     * @notice Get the power of an operator from cache
     * @param epoch The epoch number
     * @param operatorKey_ The operator key
     * @return The power of the operator
     */
    function getOperatorToPowerCached(uint48 epoch, bytes32 operatorKey_) external view returns (uint256) {
        return OBaseMiddlewareReader(address(middleware)).getOperatorToPowerCached(epoch, operatorKey_);
    }

    /**
     * @notice Get the forwarder address
     * @return The forwarder address
     */
    function getForwarderAddress() external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).getForwarderAddress();
    }

    /**
     * @notice Get the gateway contract
     * @return The gateway contract address
     */
    function getGateway() external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).getGateway();
    }

    /**
     * @notice Get the interval
     * @return The interval
     */
    function getInterval() external view returns (uint256) {
        return OBaseMiddlewareReader(address(middleware)).getInterval();
    }

    /**
     * @notice Get the last timestamp
     * @return The last timestamp
     */
    function getLastTimestamp() external view returns (uint256) {
        return OBaseMiddlewareReader(address(middleware)).getLastTimestamp();
    }

    /**
     * @notice Get the operator rewards contract address
     * @return The operator rewards contract address
     */
    function getOperatorRewardsAddress() external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).getOperatorRewardsAddress();
    }

    /**
     * @notice Get the staker rewards factory contract address
     * @return The staker rewards factory contract address
     */
    function getStakerRewardsFactoryAddress() external view returns (address) {
        return OBaseMiddlewareReader(address(middleware)).getStakerRewardsFactoryAddress();
    }

    /**
     * @dev Called by the middleware, as an auxiliary view function to check if the upkeep is needed
     * @dev The function is in this contract to reduce Middleware size
     * @return upkeepNeeded boolean to indicate whether the keeper should call performUpkeep or not.
     * @return performData bytes of the sorted (by power) operators' keys and the epoch that will be used by the keeper when calling performUpkeep, if upkeep is needed.
     */
    function auxiliaryCheckUpkeep() external view returns (bool upkeepNeeded, bytes memory performData) {
        return middleware.auxiliaryCheckUpkeep();
    }
}
