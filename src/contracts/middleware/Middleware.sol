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
//                                      OPENZEPPELIN
//**************************************************************************************************
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

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
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";

import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IMiddleware} from "../../interfaces/middleware/IMiddleware.sol";

import {SimpleKeyRegistry32} from "../libraries/SimpleKeyRegistry32.sol";

import {MapWithTimeData} from "../libraries/MapWithTimeData.sol";

contract Middleware is SimpleKeyRegistry32, Ownable, IMiddleware {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using Subnetwork for address;
    using Math for uint256;

    /**
     * @inheritdoc IMiddleware
     */
    uint48 public immutable i_epochDuration;
    /**
     * @inheritdoc IMiddleware
     */
    uint48 public immutable i_slashingWindow;
    /**
     * @inheritdoc IMiddleware
     */
    uint48 public immutable i_startTime;
    /**
     * @inheritdoc IMiddleware
     */
    address public immutable i_network;
    /**
     * @inheritdoc IMiddleware
     */
    address public immutable i_operatorRegistry;
    /**
     * @inheritdoc IMiddleware
     */
    address public immutable i_vaultRegistry;
    /**
     * @inheritdoc IMiddleware
     */
    address public immutable i_operatorNetworkOptin;
    /**
     * @inheritdoc IMiddleware
     */
    address public immutable i_owner;

    /**
     * @inheritdoc IMiddleware
     */
    uint256 public s_subnetworksCount;

    /**
     * @inheritdoc IMiddleware
     */
    address public s_operatorRewards;

    /**
     * @inheritdoc IMiddleware
     */
    mapping(uint48 epoch => uint256 amount) public s_totalStakeCache;

    /**
     * @inheritdoc IMiddleware
     */
    mapping(uint48 epoch => bool) public s_totalStakeCached;

    /**
     * @inheritdoc IMiddleware
     */
    mapping(uint48 epoch => mapping(address operator => uint256 amount)) public s_operatorStakeCache;

    EnumerableMap.AddressToUintMap private s_operators;
    EnumerableMap.AddressToUintMap private s_vaults;
    IOGateway private s_gateway;

    uint256 public constant PARTS_PER_BILLION = 1_000_000_000;

    modifier updateStakeCache(
        uint48 epoch
    ) {
        if (!s_totalStakeCached[epoch]) {
            calcAndCacheStakes(epoch);
        }
        _;
    }

    modifier onlyGateway() {
        if (msg.sender != address(s_gateway)) {
            revert Middleware__CallerNotGateway();
        }
        _;
    }

    modifier onlyIfOperatorRewardSet() {
        if (s_operatorRewards == address(0)) {
            revert Middleware__OperatorRewardsNotSet();
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
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
     */
    function updateOperatorKey(address operator, bytes32 key) external onlyOwner {
        if (!s_operators.contains(operator)) {
            revert Middleware__OperatorNotRegistred();
        }

        updateKey(operator, key);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function pauseOperator(
        address operator
    ) external onlyOwner {
        s_operators.disable(operator);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function unpauseOperator(
        address operator
    ) external onlyOwner {
        s_operators.enable(operator);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function unregisterOperator(
        address operator
    ) external onlyOwner {
        (, uint48 disabledTime) = s_operators.getTimes(operator);
        if (disabledTime == 0 || disabledTime + i_slashingWindow > Time.timestamp()) {
            revert Middleware__OperatorGracePeriodNotPassed();
        }

        s_operators.remove(operator);
    }

    /**
     * @inheritdoc IMiddleware
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
        if (slasher != address(0) && IEntity(slasher).TYPE() == uint256(SlasherType.VETO)) {
            vaultEpoch -= IVetoSlasher(slasher).vetoDuration();
        }

        if (vaultEpoch < i_slashingWindow) {
            revert Middleware__VaultEpochTooShort();
        }

        s_vaults.add(vault);
        s_vaults.enable(vault);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function pauseVault(
        address vault
    ) external onlyOwner {
        s_vaults.disable(vault);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function unpauseVault(
        address vault
    ) external onlyOwner {
        s_vaults.enable(vault);
    }

    /**
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
     */
    function setGateway(
        address _gateway
    ) external onlyOwner {
        s_gateway = IOGateway(_gateway);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function setOperatorRewardsContract(
        address operatorRewardsAddress
    ) external onlyOwner {
        if (operatorRewardsAddress == address(0)) {
            revert Middleware__InvalidAddress();
        }
        s_operatorRewards = operatorRewardsAddress;

        emit OperatorRewardContractSet(operatorRewardsAddress);
    }

    /**
     * inheritdoc IMiddleware
     */
    //TODO this will be removed and done automatically when registering a vault first time by creating staker contract from factory and then setting the mapping in operators for vault <=> staker contract
    function setStakerRewardContract(
        address stakerRewardsAddress,
        address vault
    ) external onlyOwner onlyIfOperatorRewardSet {
        IODefaultOperatorRewards(s_operatorRewards).setStakerRewardContract(stakerRewardsAddress, vault);
    }

    /**
     * inheritdoc IMiddleware
     */
    function setRewardTokenAddress(
        address rewardTokenAddress
    ) external onlyOwner onlyIfOperatorRewardSet {
        IODefaultOperatorRewards(s_operatorRewards).setTokenAddress(rewardTokenAddress);
    }

    /**
     * inheritdoc IMiddleware
     */
    function distributeRewards(
        uint256 epoch,
        uint256 eraIndex,
        uint256 totalPointsToken,
        uint256 tokensInflatedToken,
        bytes32 rewardsRoot
    ) external onlyGateway onlyIfOperatorRewardSet {
        IODefaultOperatorRewards(s_operatorRewards).distributeRewards(
            uint48(epoch), uint48(eraIndex), tokensInflatedToken, totalPointsToken, rewardsRoot
        );
    }

    /**
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
     */
    function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external onlyOwner updateStakeCache(epoch) {
        uint48 epochStartTs = getEpochStartTs(epoch);
        address operator = getOperatorByKey(operatorKey);

        // If address is 0, then we should return
        if (operator == address(0)) {
            revert Middleware__OperatorNotFound(operatorKey, epoch);
        }

        // Sanitization: check percentage is below 100% (or 1 billion in other words)
        if (percentage > PARTS_PER_BILLION) {
            revert Middleware__SlashPercentageTooBig(epoch, operator, percentage);
        }
        SlashParams memory params;
        params.epochStartTs = epochStartTs;
        params.operator = operator;
        params.slashPercentage = percentage;

        params.totalOperatorStake = getOperatorStake(operator, epoch);
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
            // Slash percentage is already in parts per billion
            // so we need to divide by a billion
            uint256 slashAmount = params.slashPercentage.mulDiv(vaultStake, PARTS_PER_BILLION);

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
        if (slasherType == uint256(SlasherType.INSTANT)) {
            ISlasher(slasher).slash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else if (slasherType == uint256(SlasherType.VETO)) {
            IVetoSlasher(slasher).requestSlash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else {
            revert Middleware__UnknownSlasherType();
        }
    }

    // **************************************************************************************************
    //                                      VIEW FUNCTIONS
    // **************************************************************************************************

    /**
     * @inheritdoc IMiddleware
     */
    function getOperatorsByEpoch(
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
     * @inheritdoc IMiddleware
     */
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory keys) {
        if (address(s_gateway) == address(0)) {
            revert Middleware__GatewayNotSet();
        }

        uint48 epoch = getCurrentEpoch();
        keys = new bytes32[](s_operators.length());

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

        s_gateway.sendOperatorsData(keys, epoch);
    }

    /**
     * @inheritdoc IMiddleware
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

            (uint256 vaultIdx, address[] memory _vaults) = getOperatorVaults(operator, epochStartTs);
            assembly {
                mstore(_vaults, vaultIdx)
            }
            if (vaultIdx > 0) {
                operatorVaultPairs[valIdx++] = OperatorVaultPair(operator, _vaults);
            }
        }
    }

    /**
     * @inheritdoc IMiddleware
     */
    function getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) public view returns (uint256 vaultIdx, address[] memory _vaults) {
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
     * @inheritdoc IMiddleware
     */
    function isVaultRegistered(
        address vault
    ) external view returns (bool) {
        return s_vaults.contains(vault);
    }

    /**
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
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
     * @inheritdoc IMiddleware
     */
    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return i_startTime + epoch * i_epochDuration;
    }

    /**
     * @inheritdoc IMiddleware
     */
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - i_startTime) / i_epochDuration;
    }

    /**
     * @inheritdoc IMiddleware
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
