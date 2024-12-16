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

import {console2} from "forge-std/console2.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {IOGateway} from "../snowbridge-override/interfaces/IOGateway.sol";
import {ParaID} from "@snowbridge/src/Types.sol";

import {SimpleKeyRegistry32} from "../libraries/SimpleKeyRegistry32.sol";
import {MapWithTimeData} from "../libraries/MapWithTimeData.sol";

contract Middleware is SimpleKeyRegistry32, Ownable {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using Subnetwork for address;

    error Middleware__NotOperator();
    error Middleware__NotVault();
    error Middleware__OperatorNotOptedIn();
    error Middleware__OperatorNotRegistred();
    error Middleware__OperarorGracePeriodNotPassed();
    error Middleware__OperatorAlreadyRegistred();
    error Middleware__VaultAlreadyRegistered();
    error Middleware__VaultEpochTooShort();
    error Middleware__VaultGracePeriodNotPassed();
    error Middleware__InvalidSubnetworksCnt();
    error Middleware__TooOldEpoch();
    error Middleware__InvalidEpoch();
    error Middleware__SlashingWindowTooShort();
    error Middleware__TooBigSlashAmount();
    error Middleware__UnknownSlasherType();

    struct ValidatorData {
        uint256 stake;
        bytes32 key;
    }

    struct SlashParams {
        uint48 epochStartTs;
        address vault;
        address operator;
        uint256 totalOperatorStake;
        uint256 slashAmount;
    }

    struct OperatorVaultPair {
        address operator;
        address[] vaults;
    }

    address public immutable i_network;
    address public immutable i_operatorRegistry;
    address public immutable i_vaultRegistry;
    address public immutable i_operatorNetworkOptin;
    address public immutable i_owner;
    uint48 public immutable i_epochDuration;
    uint48 public immutable i_slashingWindow;

    uint48 public immutable i_startTime;

    uint48 private constant INSTANT_SLASHER_TYPE = 0;
    uint48 private constant VETO_SLASHER_TYPE = 1;

    uint256 public s_subnetworksCount;
    mapping(uint48 => uint256) public s_totalStakeCache;
    mapping(uint48 => bool) public s_totalStakeCached;
    mapping(uint48 => mapping(address => uint256)) public s_operatorStakeCache;
    EnumerableMap.AddressToUintMap private s_operators;
    EnumerableMap.AddressToUintMap private s_vaults;
    IOGateway public gateway;

    modifier updateStakeCache(
        uint48 epoch
    ) {
        if (!s_totalStakeCached[epoch]) {
            calcAndCacheStakes(epoch);
        }
        _;
    }

    constructor(
        address _network,
        address _operatorRegistry,
        address _vaultRegistry,
        address _operatorNetOptin,
        address _owner,
        uint48 _epochDuration,
        uint48 _slashingWindow
    ) SimpleKeyRegistry32() Ownable(_owner) {
        if (_slashingWindow < _epochDuration) {
            revert Middleware__SlashingWindowTooShort();
        }
        i_startTime = Time.timestamp();
        i_epochDuration = _epochDuration;
        i_network = _network;
        i_owner = _owner;
        i_operatorRegistry = _operatorRegistry;
        i_vaultRegistry = _vaultRegistry;
        i_operatorNetworkOptin = _operatorNetOptin;
        i_slashingWindow = _slashingWindow;

        s_subnetworksCount = 1;
    }

    /**
     * @notice Registers a new operator with a key
     * @dev Only the owner can call this function
     * @param operator The operator's address
     * @param key The operator's key
     */
    function registerOperator(address operator, bytes32 key) external onlyOwner {
        if (s_operators.contains(operator)) {
            revert Middleware__OperatorAlreadyRegistred();
        }

        if (!IRegistry(i_operatorRegistry).isEntity(operator)) {
            revert Middleware__NotOperator();
        }

        if (!IOptInService(i_operatorNetworkOptin).isOptedIn(operator, i_network)) {
            revert Middleware__OperatorNotOptedIn();
        }

        updateKey(operator, key);

        s_operators.add(operator);
        s_operators.enable(operator);
    }

    /**
     * @notice Updates an existing operator's key
     * @dev Only the owner can call this function
     * @param operator The operator's address
     * @param key The new key
     */
    function updateOperatorKey(address operator, bytes32 key) external onlyOwner {
        if (!s_operators.contains(operator)) {
            revert Middleware__OperatorNotRegistred();
        }

        updateKey(operator, key);
    }

    /**
     * @notice Pauses an operator
     * @dev Only the owner can call this function
     * @param operator The operator to pause
     */
    function pauseOperator(
        address operator
    ) external onlyOwner {
        s_operators.disable(operator);
    }

    /**
     * @notice Re-enables a paused operator
     * @dev Only the owner can call this function
     * @param operator The operator to unpause
     */
    function unpauseOperator(
        address operator
    ) external onlyOwner {
        s_operators.enable(operator);
    }

    /**
     * @notice Removes an operator after grace period
     * @dev Only the owner can call this function
     * @param operator The operator to unregister
     */
    function unregisterOperator(
        address operator
    ) external onlyOwner {
        (, uint48 disabledTime) = s_operators.getTimes(operator);

        if (disabledTime == 0 || disabledTime + i_slashingWindow > Time.timestamp()) {
            revert Middleware__OperarorGracePeriodNotPassed();
        }

        s_operators.remove(operator);
    }

    /**
     * @notice Registers a new vault
     * @dev Only the owner can call this function
     * @param vault The vault address to register
     */
    function registerVault(
        address vault
    ) external onlyOwner {
        if (s_vaults.contains(vault)) {
            revert Middleware__VaultAlreadyRegistered();
        }

        if (!IRegistry(i_vaultRegistry).isEntity(vault)) {
            revert Middleware__NotVault();
        }

        uint48 vaultEpoch = IVault(vault).epochDuration();

        address slasher = IVault(vault).slasher();
        if (slasher != address(0) && IEntity(slasher).TYPE() == VETO_SLASHER_TYPE) {
            vaultEpoch -= IVetoSlasher(slasher).vetoDuration();
        }

        if (vaultEpoch < i_slashingWindow) {
            revert Middleware__VaultEpochTooShort();
        }

        s_vaults.add(vault);
        s_vaults.enable(vault);
    }

    /**
     * @notice Pauses a vault
     * @dev Only the owner can call this function
     * @param vault The vault to pause
     */
    function pauseVault(
        address vault
    ) external onlyOwner {
        s_vaults.disable(vault);
    }

    /**
     * @notice Re-enables a paused vault
     * @dev Only the owner can call this function
     * @param vault The vault to unpause
     */
    function unpauseVault(
        address vault
    ) external onlyOwner {
        s_vaults.enable(vault);
    }

    /**
     * @notice Removes a vault after grace period
     * @dev Only the owner can call this function
     * @param vault The vault to unregister
     */
    function unregisterVault(
        address vault
    ) external onlyOwner {
        (, uint48 disabledTime) = s_vaults.getTimes(vault);

        if (disabledTime == 0 || disabledTime + i_slashingWindow > Time.timestamp()) {
            revert Middleware__VaultGracePeriodNotPassed();
        }

        s_vaults.remove(vault);
    }

    /**
     * @notice Updates the number of subnetworks
     * @dev Only the owner can call this function
     * @param _subnetworksCount New subnetwork count
     */
    function setSubnetworksCount(
        uint256 _subnetworksCount
    ) external onlyOwner {
        if (s_subnetworksCount >= _subnetworksCount) {
            revert Middleware__InvalidSubnetworksCnt();
        }

        s_subnetworksCount = _subnetworksCount;
    }

    /**
     * @notice Sets the gateway contract
     * @dev Only the owner can call this function
     * @param _gateway The gateway contract address
     */
    function setGateway(
        address _gateway
    ) external onlyOwner {
        gateway = IOGateway(_gateway);
    }

    // function submission(bytes memory payload, bytes32[] memory signatures) public updateStakeCache(getCurrentEpoch()) {
    //     // validate signatures
    //     // validate payload
    //     // process payload
    // }

    /**
     * @notice Calculates and caches stakes for an epoch
     * @param epoch The epoch to calculate for
     * @return totalStake The total stake amount
     */
    function calcAndCacheStakes(
        uint48 epoch
    ) public returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than SLASHING_WINDOW total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - i_slashingWindow) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }

        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            uint256 operatorStake = getOperatorStake(operator, epoch);
            s_operatorStakeCache[epoch][operator] = operatorStake;

            totalStake += operatorStake;
        }

        s_totalStakeCached[epoch] = true;
        s_totalStakeCache[epoch] = totalStake;
    }

    /**
     * @notice Slashes an operator's stake
     * @dev Only the owner can call this function
     * @dev This function first updates the stake cache for the target epoch
     * @param epoch The epoch number
     * @param operator The operator to slash
     * @param amount Amount to slash
     */
    //INFO: this function can be made external. To check if it is possible to make it external
    function slash(uint48 epoch, address operator, uint256 amount) public onlyOwner updateStakeCache(epoch) {
        SlashParams memory params;
        params.epochStartTs = getEpochStartTs(epoch);
        params.operator = operator;
        params.slashAmount = amount;

        params.totalOperatorStake = getOperatorStake(operator, epoch);

        if (params.totalOperatorStake < amount) {
            revert Middleware__TooBigSlashAmount();
        }
        // simple pro-rata slasher
        for (uint256 i; i < s_vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = s_vaults.atWithTimes(i);
            // just skip the vault if it was enabled after the target epoch or not enabled
            if (!_wasActiveAt(enabledTime, disabledTime, params.epochStartTs)) {
                continue;
            }

            _processVaultSlashing(vault, params);
        }
    }

    /**
     * @dev Get vault stake and calculate slashing amount.
     * @param vault The vault address to calculate its stake
     * @param params Struct containing slashing parameters
     */
    function _processVaultSlashing(address vault, SlashParams memory params) private {
        for (uint96 j = 0; j < s_subnetworksCount; ++j) {
            bytes32 subnetwork = i_network.subnetwork(j);
            //! This can be manipulated. I get slashed for 100 ETH, but if I participate to multiple vaults without any slashing, I can get slashed for far lower amount of ETH
            uint256 vaultStake = IBaseDelegator(IVault(vault).delegator()).stakeAt(
                subnetwork, params.operator, params.epochStartTs, new bytes(0)
            );
            uint256 slashAmount = (params.slashAmount * vaultStake) / params.totalOperatorStake;
            _slashVault(params.epochStartTs, vault, subnetwork, params.operator, slashAmount);
        }
    }

    /**
     * @dev Slashes a vault's stake for a specific operator
     * @param timestamp Time at which the epoch started
     * @param vault Address of the vault to slash
     * @param subnetwork Subnetwork identifier
     * @param operator Address of the operator being slashed
     * @param amount Amount to slash
     */
    function _slashVault(
        uint48 timestamp,
        address vault,
        bytes32 subnetwork,
        address operator,
        uint256 amount
    ) private {
        address slasher = IVault(vault).slasher();
        if (slasher == address(0) || amount == 0) {
            return;
        }
        uint256 slasherType = IEntity(slasher).TYPE();
        if (slasherType == INSTANT_SLASHER_TYPE) {
            ISlasher(slasher).slash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else if (slasherType == VETO_SLASHER_TYPE) {
            IVetoSlasher(slasher).requestSlash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else {
            revert Middleware__UnknownSlasherType();
        }
    }

    // **************************************************************************************************
    //                                      VIEW FUNCTIONS
    // **************************************************************************************************

    /**
     * @notice Gets how many operators were active at a specific epoch
     * @param epoch The epoch at which to check how many operators were active
     * @return activeOperators The array of active operators
     */
    function getCurrentOperators(
        uint48 epoch
    ) external view returns (address[] memory activeOperators) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        activeOperators = new address[](s_operators.length());
        uint256 valIdx = 0;
        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            activeOperators[valIdx++] = operator;
        }

        assembly {
            mstore(activeOperators, valIdx)
        }
    }

    /**
     * @notice Gets the operators' keys for latest epoch
     * @return keys Array of operator keys
     */
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory keys) {
        uint48 epoch = getCurrentEpoch();
        keys = new bytes32[](s_operators.length());
        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator,,) = s_operators.atWithTimes(i);
            keys[i] = getCurrentOperatorKey(operator);
        }

        uint48 epochStartTs = getEpochStartTs(epoch);
        uint256 valIdx = 0;
        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            keys[valIdx++] = getCurrentOperatorKey(operator);
        }

        assembly {
            mstore(keys, valIdx)
        }

        gateway.sendOperatorsData(keys, ParaID.wrap(1));
    }

    /**
     * @notice Gets operator-vault pairs for an epoch
     * @param epoch The epoch number
     * @return operatorVaultPairs Array of operator-vault pairs
     */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (OperatorVaultPair[] memory operatorVaultPairs) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        operatorVaultPairs = new OperatorVaultPair[](s_operators.length());
        uint256 valIdx = 0;
        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            (uint256 vaultIdx, address[] memory _vaults) = _getOperatorVaults(operator, epochStartTs);
            assembly {
                mstore(_vaults, vaultIdx)
            }
            if (vaultIdx > 0) {
                operatorVaultPairs[valIdx++] = OperatorVaultPair(operator, _vaults);
            }
        }
    }

    function _getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) private view returns (uint256 vaultIdx, address[] memory _vaults) {
        _vaults = new address[](s_vaults.length());
        vaultIdx = 0;
        for (uint256 j; j < s_vaults.length(); ++j) {
            (address vault, uint48 vaultEnabledTime, uint48 vaultDisabledTime) = s_vaults.atWithTimes(j);

            // just skip the vault if it was enabled after the target epoch or not enabled
            if (!_wasActiveAt(vaultEnabledTime, vaultDisabledTime, epochStartTs)) {
                continue;
            }
            uint256 operatorStake = 0;
            for (uint96 k = 0; k < s_subnetworksCount; ++k) {
                operatorStake += IBaseDelegator(IVault(vault).delegator()).stakeAt(
                    i_network.subnetwork(k), operator, epochStartTs, new bytes(0)
                );
            }

            if (operatorStake > 0) {
                _vaults[vaultIdx++] = vault;
            }
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
        return s_vaults.contains(vault);
    }

    /**
     * @notice Gets operator's stake for an epoch
     * @param operator The operator address
     * @param epoch The epoch number
     * @return stake The operator's total stake
     */
    function getOperatorStake(address operator, uint48 epoch) public view returns (uint256 stake) {
        if (s_totalStakeCached[epoch]) {
            return s_operatorStakeCache[epoch][operator];
        }

        uint48 epochStartTs = getEpochStartTs(epoch);
        for (uint256 i; i < s_vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = s_vaults.atWithTimes(i);

            // just skip the vault if it was enabled after the target epoch or not enabled
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            for (uint96 j = 0; j < s_subnetworksCount; ++j) {
                stake += IBaseDelegator(IVault(vault).delegator()).stakeAt(
                    i_network.subnetwork(j), operator, epochStartTs, new bytes(0)
                );
            }
        }
        return stake;
    }

    /**
     * @notice Gets total stake for an epoch
     * @param epoch The epoch number
     * @return Total stake amount
     */
    function getTotalStake(
        uint48 epoch
    ) public view returns (uint256) {
        if (s_totalStakeCached[epoch]) {
            return s_totalStakeCache[epoch];
        }
        return _calcTotalStake(epoch);
    }

    /**
     * @notice Gets validator set for an epoch
     * @param epoch The epoch number
     * @return validatorsData Array of validator data
     */
    function getValidatorSet(
        uint48 epoch
    ) public view returns (ValidatorData[] memory validatorsData) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        validatorsData = new ValidatorData[](s_operators.length());
        uint256 valIdx = 0;

        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            bytes32 key = getOperatorKeyAt(operator, epochStartTs);
            if (key == bytes32(0)) {
                continue;
            }

            uint256 stake = getOperatorStake(operator, epoch);

            validatorsData[valIdx++] = ValidatorData(stake, key);
        }

        // shrink array to skip unused slots
        /// @solidity memory-safe-assembly
        assembly {
            mstore(validatorsData, valIdx)
        }
    }

    /**
     * @notice Gets the timestamp when an epoch starts
     * @param epoch The epoch number
     * @return timestamp The start time of the epoch
     */
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return i_startTime + epoch * i_epochDuration;
    }

    /**
     * @notice Determines which epoch a timestamp belongs to
     * @param timestamp The timestamp to check
     * @return epoch The corresponding epoch number
     */
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - i_startTime) / i_epochDuration;
    }

    /**
     * @notice Gets the current epoch number
     * @return epoch The current epoch
     */
    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    /**
     * @dev Calculates total stake for an epoch
     * @param epoch The epoch to calculate stake for
     * @return totalStake The total stake amount
     */
    function _calcTotalStake(
        uint48 epoch
    ) private view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than i_slashingWindow total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - i_slashingWindow) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }

        for (uint256 i; i < s_operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = s_operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            uint256 operatorStake = getOperatorStake(operator, epoch);
            totalStake += operatorStake;
        }
    }

    /**
     * @dev Checks if an entity was active at a specific timestamp
     * @param enabledTime Time when entity was enabled
     * @param disabledTime Time when entity was disabled (0 if never disabled)
     * @param timestamp Timestamp to check activity for
     * @return bool True if entity was active at timestamp
     */
    function _wasActiveAt(uint48 enabledTime, uint48 disabledTime, uint48 timestamp) private pure returns (bool) {
        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }
}
