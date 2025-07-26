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
//                                      CHAINLINK
//**************************************************************************************************
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {PauseableEnumerableSet} from "@symbiotic-middleware/libraries/PauseableEnumerableSet.sol";
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
import {OperatorManager} from "@symbiotic-middleware/managers/OperatorManager.sol";
import {KeyManager256} from "@symbiotic-middleware/extensions/managers/keys/KeyManager256.sol";
import {BaseMiddleware} from "@symbiotic-middleware/middleware/BaseMiddleware.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {QuickSort} from "src/contracts/libraries/QuickSort.sol";
import {MiddlewareStorage} from "src/contracts/middleware/MiddlewareStorage.sol";

/**
 * @title OBaseMiddlewareReader
 * @notice An overridden version of the core Symbiotic helper contract for view functions that combines core manager functionality
 * @dev This contract serves as a foundation for building custom middleware by providing essential
 * management capabilities that can be extended with additional functionality.
 */
contract OBaseMiddlewareReader is
    // IOBaseMiddlewareReader, not included since multiple methods collide with other inherited contracts
    MiddlewareStorage,
    EpochCapture,
    VaultManager,
    OperatorManager,
    KeyManager256
{
    using QuickSort for IMiddleware.ValidatorData[];
    using PauseableEnumerableSet for PauseableEnumerableSet.AddressSet;
    using PauseableEnumerableSet for PauseableEnumerableSet.Status;
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    // ** OLD BASE MIDDLEWARE READER LOGIC **

    function stakeToPower(address vault, uint256 stake) public view override returns (uint256 power) {
        return BaseMiddleware(_getMiddleware()).stakeToPower(vault, stake);
    }

    /**
     * @notice Converts stake amount to voting power in USD
     * @param vault The vault address
     * @param stake The stake amount
     * @return power The calculated voting power (equal to stake)
     */
    function getPowerInUSD(address vault, uint256 stake) public view returns (uint256 power) {
        if (stake == 0) {
            return 0;
        }

        address collateral = vaultToCollateral(vault);
        address oracle = collateralToOracle(collateral);

        if (oracle == address(0)) {
            revert IOBaseMiddlewareReader.OBaseMiddlewareReader__NotSupportedCollateral(collateral);
        }
        (, int256 price,,,) = AggregatorV3Interface(oracle).latestRoundData();
        uint8 priceDecimals = AggregatorV3Interface(oracle).decimals();
        power = stake.mulDiv(uint256(price), 10 ** priceDecimals);
        // Normalize power to 18 decimals
        uint8 collateralDecimals = IERC20Metadata(collateral).decimals();
        if (collateralDecimals != DEFAULT_DECIMALS) {
            power = power.mulDiv(10 ** DEFAULT_DECIMALS, 10 ** collateralDecimals);
        }
    }

    /**
     * @notice Gets the network address
     * @return The network address
     */
    function NETWORK() external view returns (address) {
        return _NETWORK();
    }

    /**
     * @notice Gets the slashing window
     * @return The slashing window
     */
    function SLASHING_WINDOW() external view returns (uint48) {
        return _SLASHING_WINDOW();
    }

    /**
     * @notice Gets the vault registry address
     * @return The vault registry address
     */
    function VAULT_REGISTRY() external view returns (address) {
        return _VAULT_REGISTRY();
    }

    /**
     * @notice Gets the operator registry address
     * @return The operator registry address
     */
    function OPERATOR_REGISTRY() external view returns (address) {
        return _OPERATOR_REGISTRY();
    }

    /**
     * @notice Gets the operator net opt-in address
     * @return The operator net opt-in address
     */
    function OPERATOR_NET_OPTIN() external view returns (address) {
        return _OPERATOR_NET_OPTIN();
    }

    /**
     * @notice Gets the number of operators
     * @return The number of operators
     */
    function operatorsLength() external view returns (uint256) {
        return _operatorsLength();
    }

    /**
     * @notice Gets the operator and its times at a specific position
     * @param pos The position
     * @return The operator address, start time, and end time
     */
    function operatorWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48) {
        return _operatorWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active operators
     * @return The list of active operators
     */
    function activeOperators() external view returns (address[] memory) {
        return _activeOperators();
    }

    /**
     * @notice Gets the list of active operators at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active operators at the given timestamp
     */
    function activeOperatorsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return _activeOperatorsAt(timestamp);
    }

    /**
     * @notice Checks if an operator was active at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return True if the operator was active at the given timestamp, false otherwise
     */
    function operatorWasActiveAt(uint48 timestamp, address operator) external view returns (bool) {
        return _operatorWasActiveAt(timestamp, operator);
    }

    /**
     * @notice Checks if an operator is registered
     * @param operator The operator address
     * @return True if the operator is registered, false otherwise
     */
    function isOperatorRegistered(
        address operator
    ) external view returns (bool) {
        return _isOperatorRegistered(operator);
    }

    /**
     * @notice Gets the number of subnetworks
     * @return The number of subnetworks
     */
    function subnetworksLength() external view returns (uint256) {
        return _subnetworksLength();
    }

    /**
     * @notice Gets the subnetwork and its times at a specific position
     * @param pos The position
     * @return The subnetwork address, start time, and end time
     */
    function subnetworkWithTimesAt(
        uint256 pos
    ) external view returns (uint160, uint48, uint48) {
        return _subnetworkWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active subnetworks
     * @return The list of active subnetworks
     */
    function activeSubnetworks() external view returns (uint160[] memory) {
        return _activeSubnetworks();
    }

    /**
     * @notice Gets the list of active subnetworks at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active subnetworks at the given timestamp
     */
    function activeSubnetworksAt(
        uint48 timestamp
    ) external view returns (uint160[] memory) {
        return _activeSubnetworksAt(timestamp);
    }

    /**
     * @notice Checks if a subnetwork was active at a specific timestamp
     * @param timestamp The timestamp
     * @param subnetwork The subnetwork address
     * @return True if the subnetwork was active at the given timestamp, false otherwise
     */
    function subnetworkWasActiveAt(uint48 timestamp, uint96 subnetwork) external view returns (bool) {
        return _subnetworkWasActiveAt(timestamp, subnetwork);
    }

    /**
     * @notice Gets the number of shared vaults
     * @return The number of shared vaults
     */
    function sharedVaultsLength() external view returns (uint256) {
        return _sharedVaultsLength();
    }

    /**
     * @notice Gets the shared vault and its times at a specific position
     * @param pos The position
     * @return The shared vault address, start time, and end time
     */
    function sharedVaultWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48) {
        return _sharedVaultWithTimesAt(pos);
    }

    /**
     * @notice Gets the list of active shared vaults
     * @return The list of active shared vaults
     */
    function activeSharedVaults() external view returns (address[] memory) {
        return _activeSharedVaults();
    }

    /**
     * @notice Gets the list of active shared vaults at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active shared vaults at the given timestamp
     */
    function activeSharedVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return _activeSharedVaultsAt(timestamp);
    }

    /**
     * @notice Gets the number of vaults for a specific operator
     * @param operator The operator address
     * @return The number of vaults for the given operator
     */
    function operatorVaultsLength(
        address operator
    ) external view returns (uint256) {
        return _operatorVaultsLength(operator);
    }

    /**
     * @notice Gets the operator vault and its times at a specific position
     * @param operator The operator address
     * @param pos The position
     * @return The operator vault address, start time, and end time
     */
    function operatorVaultWithTimesAt(address operator, uint256 pos) external view returns (address, uint48, uint48) {
        return _operatorVaultWithTimesAt(operator, pos);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator
     * @param operator The operator address
     * @return The list of active vaults for the given operator
     */
    function activeOperatorVaults(
        address operator
    ) external view returns (address[] memory) {
        return _activeOperatorVaults(operator);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The list of active vaults for the given operator at the given timestamp
     */
    function activeOperatorVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory) {
        return _activeOperatorVaultsAt(timestamp, operator);
    }

    /**
     * @notice Gets the list of active vaults
     * @return The list of active vaults
     */
    function activeVaults() external view returns (address[] memory) {
        return _activeVaults();
    }

    /**
     * @notice Gets the list of active vaults at a specific timestamp
     * @param timestamp The timestamp
     * @return The list of active vaults at the given timestamp
     */
    function activeVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory) {
        return _activeVaultsAt(timestamp);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator
     * @param operator The operator address
     * @return The list of active vaults for the given operator
     */
    function activeVaults(
        address operator
    ) external view returns (address[] memory) {
        return _activeVaults(operator);
    }

    /**
     * @notice Gets the list of active vaults for a specific operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The list of active vaults for the given operator at the given timestamp
     */
    function activeVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory) {
        return _activeVaultsAt(timestamp, operator);
    }

    /**
     * @notice Checks if a vault was active at a specific timestamp for a specific operator
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vault The vault address
     * @return True if the vault was active at the given timestamp for the given operator, false otherwise
     */
    function vaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool) {
        return _vaultWasActiveAt(timestamp, operator, vault);
    }

    /**
     * @notice Checks if a shared vault was active at a specific timestamp
     * @param timestamp The timestamp
     * @param vault The shared vault address
     * @return True if the shared vault was active at the given timestamp, false otherwise
     */
    function sharedVaultWasActiveAt(uint48 timestamp, address vault) external view returns (bool) {
        return _sharedVaultWasActiveAt(timestamp, vault);
    }

    /**
     * @notice Checks if an operator vault was active at a specific timestamp for a specific operator
     * @param timestamp The timestamp
     * @param operator The operator address
     * @param vault The vault address
     * @return True if the operator vault was active at the given timestamp for the given operator, false otherwise
     */
    function operatorVaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool) {
        return _operatorVaultWasActiveAt(timestamp, operator, vault);
    }

    /**
     * @notice Gets the power of an operator for a specific vault and subnetwork
     * @param operator The operator address
     * @param vault The vault address
     * @param subnetwork The subnetwork address
     * @return The power of the operator for the given vault and subnetwork
     */
    function getOperatorPower(address operator, address vault, uint96 subnetwork) external view returns (uint256) {
        return _getOperatorPower(operator, vault, subnetwork);
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
        return _getOperatorPowerAt(timestamp, operator, vault, subnetwork);
    }

    /**
     * @notice Gets the power of an operator
     * @param operator The operator address
     * @return The power of the operator
     */
    function getOperatorPower(
        address operator
    ) external view returns (uint256) {
        return _getOperatorPower(operator);
    }

    /**
     * @notice Gets the power of an operator at a specific timestamp
     * @param timestamp The timestamp
     * @param operator The operator address
     * @return The power of the operator at the given timestamp
     */
    function getOperatorPowerAt(uint48 timestamp, address operator) external view returns (uint256) {
        return _getOperatorPowerAt(timestamp, operator);
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
        return _getOperatorPower(operator, vaults, subnetworks);
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
        return _getOperatorPowerAt(timestamp, operator, vaults, subnetworks);
    }

    /**
     * @notice Gets the total power of a list of operators
     * @param operators The list of operator addresses
     * @return The total power of the given operators
     */
    function totalPower(
        address[] memory operators
    ) external view returns (uint256) {
        return _totalPower(operators);
    }
    /**
     * @notice Gets the middleware address from the calldata
     * @return The middleware address
     */

    function _getMiddleware() private pure returns (address) {
        address middleware;
        assembly {
            middleware := shr(96, calldataload(sub(calldatasize(), 20)))
        }
        return middleware;
    }

    //** END OLD BASE MIDDLEWARE READER **

    /**
     * @notice Gets how many operators were active at a specific epoch
     * @param epoch The epoch at which to check how many operators were active
     * @return activeOperators_ The array of active operators
     */
    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory activeOperators_) {
        uint48 epochStartTs = getEpochStart(epoch);
        activeOperators_ = _activeOperatorsAt(epochStartTs);
    }

    /**
     * @notice Gets operator-vault pairs for an epoch
     * @param epoch The epoch number
     * @return operatorVaultPairs Array of operator-vault pairs
     */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (IMiddleware.OperatorVaultPair[] memory operatorVaultPairs) {
        uint48 epochStartTs = getEpochStart(epoch);
        address[] memory operators = _activeOperatorsAt(epochStartTs);

        operatorVaultPairs = new IMiddleware.OperatorVaultPair[](operators.length);

        uint256 valIdx = 0;
        uint256 operatorsLength_ = operators.length;
        for (uint256 i; i < operatorsLength_;) {
            address operator = operators[i];
            (uint256 vaultIdx, address[] memory _vaults) = getOperatorVaults(operator, epochStartTs);

            if (vaultIdx != 0) {
                operatorVaultPairs[valIdx++] = IMiddleware.OperatorVaultPair(operator, _vaults);
            }
            unchecked {
                ++i;
            }
        }

        assembly ("memory-safe") {
            mstore(operatorVaultPairs, valIdx)
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
        VaultManagerStorage storage $ = _getVaultManagerStorage();
        return $._sharedVaults.contains(vault);
    }

    /**
     * @dev Sorts operators by their total power in descending order, after 500 it will be almost impossible to be used on-chain since 500 ≈ 36M gas
     * @param epoch The epoch number
     * @return sortedKeys Array of sorted operators keys based on their power
     */
    function sortOperatorsByPower(
        uint48 epoch
    ) public view returns (bytes32[] memory sortedKeys) {
        IMiddleware.ValidatorData[] memory validatorSet = getValidatorSet(epoch);
        if (validatorSet.length == 0) return sortedKeys;
        validatorSet = validatorSet.quickSort(0, int256(validatorSet.length - 1));

        sortedKeys = new bytes32[](validatorSet.length);
        uint256 validatorSetLength = validatorSet.length;
        for (uint256 i; i < validatorSetLength;) {
            sortedKeys[i] = validatorSet[i].key;
            unchecked {
                ++i;
            }
        }
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
        address[] memory operatorVaults = _activeVaultsAt(epochStartTs, operator);
        vaults = new address[](operatorVaults.length);
        bytes32 subnetwork = _NETWORK().subnetwork(0);

        uint256 operatorVaultsLength_ = operatorVaults.length;
        for (uint256 j; j < operatorVaultsLength_;) {
            address _vault = operatorVaults[j];

            uint256 operatorStake =
                IBaseDelegator(IVault(_vault).delegator()).stakeAt(subnetwork, operator, epochStartTs, hex"");

            unchecked {
                if (operatorStake != 0) {
                    vaults[vaultIdx++] = _vault;
                }

                ++j;
            }
        }
        assembly ("memory-safe") {
            mstore(vaults, vaultIdx)
        }
    }

    /**
     * @notice Gets total stake for an epoch
     * @param epoch The epoch number
     * @return totalStake Total stake amount
     */
    function getTotalStake(
        uint48 epoch
    ) external view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStart(epoch);

        address[] memory operators = _activeOperatorsAt(epochStartTs);
        uint256 operatorsLength_ = operators.length;
        for (uint256 i; i < operatorsLength_;) {
            uint256 operatorStake = _getOperatorPowerAt(epochStartTs, operators[i]);
            totalStake += operatorStake;
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Gets an operator's active key at the current capture timestamp
     * @param operator The operator address to lookup
     * @return The operator's active key encoded as bytes, or encoded zero bytes if none
     */
    function getOperatorKeyAt(address operator, uint48 timestamp) public view returns (bytes memory) {
        KeyManager256Storage storage $ = _getKeyManager256Storage();
        bytes32 key = $._key[operator];
        if (key != bytes32(0) && $._keyData[key].status.wasActiveAt(timestamp)) {
            return abi.encode(key);
        }
        key = $._prevKey[operator];
        if (key != bytes32(0) && $._keyData[key].status.wasActiveAt(timestamp)) {
            return abi.encode(key);
        }
        return abi.encode(bytes32(0));
    }

    /**
     * @notice Gets validator set for an epoch
     * @param epoch The epoch number
     * @return validatorSet validatorsData Array of validator data
     */
    function getValidatorSet(
        uint48 epoch
    ) public view returns (IMiddleware.ValidatorData[] memory validatorSet) {
        uint48 epochStartTs = getEpochStart(epoch);
        address[] memory operators = _activeOperatorsAt(epochStartTs);
        validatorSet = new IMiddleware.ValidatorData[](operators.length);

        uint256 len = 0;
        VaultManagerStorage storage $ = _getVaultManagerStorage();
        address[] memory sharedVaults = $._sharedVaults.getActive(epochStartTs);
        uint96 subnetwork = _NETWORK().subnetwork(0).identifier();
        uint256 operatorsLength_ = operators.length;
        for (uint256 i; i < operatorsLength_;) {
            address operator = operators[i];
            bytes32 key = abi.decode(getOperatorKeyAt(operator, epochStartTs), (bytes32));
            uint256 operatorPowerCached = getOperatorToPower(epoch, key);

            unchecked {
                ++i;

                if (operatorPowerCached != 0) {
                    validatorSet[len++] = IMiddleware.ValidatorData(operatorPowerCached, key);
                } else {
                    uint256 power = _optmizedGetOperatorPowerAt(epochStartTs, sharedVaults, subnetwork, operator);
                    if (key != bytes32(0) && power != 0) {
                        validatorSet[len++] = IMiddleware.ValidatorData(power, key);
                    }
                }
            }
        }

        // shrink array to skip unused slots
        assembly ("memory-safe") {
            mstore(validatorSet, len)
        }
    }

    /**
     * @notice Determines which epoch a timestamp belongs to
     * @param timestamp The timestamp to check
     * @return epoch The corresponding epoch number
     */
    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48 epoch) {
        EpochCaptureStorage storage $ = _getEpochCaptureStorage();
        return (timestamp - $.startTimestamp - 1) / $.epochDuration;
    }

    /**
     * @dev Called by the middleware, as an auxiliary view function to check if the upkeep is needed
     * @dev The function is in this contract to reduce Middleware size
     * @return upkeepNeeded boolean to indicate whether the keeper should call performUpkeep or not.
     * @return performData bytes of the sorted (by power) operators' keys and the epoch that will be used by the keeper when calling performUpkeep, if upkeep is needed.
     */
    function auxiliaryCheckUpkeep() external view returns (bool upkeepNeeded, bytes memory performData) {
        uint48 epoch = getCurrentEpoch();
        uint48 currentEpochStartTs = getEpochStart(epoch);

        StorageMiddleware storage $ = _getMiddlewareStorage();
        StorageMiddlewareCache storage cache = _getMiddlewareStorageCache();

        address[] memory activeOperators_ = _activeOperators();
        uint256 activeOperatorsLength = activeOperators_.length;
        if (activeOperatorsLength == 0) {
            // No active operators, no upkeep needed
            return (false, hex"");
        }

        uint256 cacheIndex = cache.epochToCacheIndex[epoch];
        uint256 pendingOperatorsToCache = activeOperatorsLength - cacheIndex;

        // Check if cache is still not filled with the current epoch validators
        if (pendingOperatorsToCache > 0) {
            uint256 maxNumOperatorsToCheck = Math.min(pendingOperatorsToCache, MAX_OPERATORS_TO_PROCESS);
            IMiddleware.ValidatorData[] memory validatorsData =
                _getValidatorDataForOperators(maxNumOperatorsToCheck, cacheIndex, currentEpochStartTs, activeOperators_);

            // encode values to be used in performUpkeep
            return (true, abi.encode(CACHE_DATA_COMMAND, validatorsData));
        }

        //Should be at least once per epoch
        upkeepNeeded = (Time.timestamp() - $.lastTimestamp) > $.interval;
        if (upkeepNeeded) {
            // This will use the cached values, resulting in just a simple sorting operation. We can know a priori how much it cost since it's just an address with a uint256 power. Worst case we can split this too.
            bytes32[] memory sortedKeys = sortOperatorsByPower(epoch);
            performData = abi.encode(SEND_DATA_COMMAND, sortedKeys);
            return (true, performData);
        }

        return (upkeepNeeded, hex"");
    }

    function _getValidatorDataForOperators(
        uint256 maxNumOperatorsToCheck,
        uint256 cacheIndex,
        uint48 timestamp,
        address[] memory activeOperators_
    ) private view returns (IMiddleware.ValidatorData[] memory validatorsData) {
        // Populate validatorsData with the new operators' keys and their powers
        // It gets encoded to be used in performUpkeep
        validatorsData = new IMiddleware.ValidatorData[](maxNumOperatorsToCheck);

        VaultManagerStorage storage $ = _getVaultManagerStorage();
        address[] memory sharedVaults = $._sharedVaults.getActive(timestamp);
        uint96 subnetwork = _NETWORK().subnetwork(0).identifier();
        uint256 activeOperatorsLength = activeOperators_.length;

        for (uint256 i = cacheIndex; i < cacheIndex + maxNumOperatorsToCheck && i < activeOperatorsLength;) {
            address operator = activeOperators_[i];
            bytes32 operatorKey = abi.decode(operatorKey(operator), (bytes32));
            uint256 operatorPower = _optmizedGetOperatorPowerAt(timestamp, sharedVaults, subnetwork, operator);
            validatorsData[i - cacheIndex] = IMiddleware.ValidatorData({key: operatorKey, power: operatorPower});

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev If an operator can be active more than MAX_ACTIVE_VAULTS, we ignore it by letting power be 0. This is necessary because after the threshold, slashing and distributing rewards will revert due to max execution gas.
     * @dev This version is mostly redundant with vault manager code, but it is optimized because it only gets shared vaults and subnetworks once. The original version does it for each operator.
     */
    function _optmizedGetOperatorPowerAt(
        uint48 timestamp,
        address[] memory sharedVaults,
        uint96 subnetwork,
        address operator
    ) private view returns (uint256 power) {
        VaultManagerStorage storage $ = _getVaultManagerStorage();
        address[] memory operatorVaults = $._operatorVaults[operator].getActive(timestamp);

        // This check might seem innecesary since we check on vault registration, however if we register first operator vaults and then shared ones, the limit might be reached for an operator without triggering the revert on registration.
        if (sharedVaults.length + operatorVaults.length <= MAX_ACTIVE_VAULTS) {
            power = _getOperatorPowerAt(timestamp, operator, sharedVaults, subnetwork)
                + _getOperatorPowerAt(timestamp, operator, operatorVaults, subnetwork);
        }
    }

    /**
     * @notice Optimized version of _getOperatorPowerAt that only gets the power for a single subnetwork
     * @param timestamp The timestamp to check
     * @param operator The operator address
     * @param vaults The list of vault addresses
     * @param subnetwork The subnetwork identifier
     * @return power The total power amount at the timestamp
     */
    function _getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address[] memory vaults,
        uint96 subnetwork
    ) internal view returns (uint256 power) {
        uint256 vaultsLength = vaults.length;
        for (uint256 i; i < vaultsLength; ++i) {
            power += _getOperatorPowerAt(timestamp, operator, vaults[i], subnetwork);
        }

        return power;
    }
}
