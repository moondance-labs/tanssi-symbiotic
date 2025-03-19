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
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {Operators} from "@symbiotic-middleware/extensions/operators/Operators.sol";
import {KeyManager256} from "@symbiotic-middleware/extensions/managers/keys/KeyManager256.sol";
import {OzAccessControl} from "@symbiotic-middleware/extensions/managers/access/OzAccessControl.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {PauseableEnumerableSet} from "@symbiotic-middleware/libraries/PauseableEnumerableSet.sol";
//**************************************************************************************************
//                                      SNOWBRIDGE
//**************************************************************************************************
import {IOGateway} from "@tanssi-bridge-relayer/snowbridge/contracts/src/interfaces/IOGateway.sol";
import {IODefaultStakerRewards} from "src/interfaces/rewarder/IODefaultStakerRewards.sol";
import {IODefaultOperatorRewards} from "src/interfaces/rewarder/IODefaultOperatorRewards.sol";
import {IODefaultStakerRewardsFactory} from "src/interfaces/rewarder/IODefaultStakerRewardsFactory.sol";
import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";
import {OSharedVaults} from "src/contracts/extensions/OSharedVaults.sol";
import {MiddlewareStorage} from "src/contracts/middleware/MiddlewareStorage.sol";

import {QuickSort} from "../libraries/QuickSort.sol";

contract Middleware is
    UUPSUpgradeable,
    OSharedVaults,
    Operators,
    KeyManager256,
    OzAccessControl,
    EpochCapture,
    MiddlewareStorage,
    IMiddleware
{
    using QuickSort for ValidatorData[];
    using PauseableEnumerableSet for PauseableEnumerableSet.AddressSet;
    using PauseableEnumerableSet for PauseableEnumerableSet.Status;
    using Subnetwork for address;
    using Math for uint256;

    modifier updateStakeCache(
        uint48 epoch
    ) {
        if (!totalStakeIsCached(epoch)) {
            calcAndCacheStakes(epoch);
        }
        _;
    }

    // TODO should use AccessControl instead of this modifier
    // Add Gateway Role and use checkAccess modifier
    modifier onlyGateway() {
        if (msg.sender != address(getGateway())) {
            revert Middleware__CallerNotGateway();
        }
        _;
    }

    /*
     * @notice Constructor for the middleware
     * @param operatorRewards The operator rewards address
     * @param stakerRewardsFactory The staker rewards factory address
     */
    constructor(address operatorRewards, address stakerRewardsFactory) {
        _disableInitializers();

        if (operatorRewards == address(0) || stakerRewardsFactory == address(0)) {
            revert Middleware__InvalidAddress();
        }

        i_operatorRewards = operatorRewards;
        i_stakerRewardsFactory = stakerRewardsFactory;
    }

    /*
     * @notice Initialize the middleware
     * @param network The network address
     * @param operatorRegistry The operator registry address
     * @param vaultRegistry The vault registry address
     * @param operatorNetOptin The operator network optin address
     * @param owner The owner address
     * @param epochDuration The epoch duration
     * @param slashingWindow The slashing window
     * @param reader The reader address
     */
    function initialize(
        address network,
        address operatorRegistry,
        address vaultRegistry,
        address operatorNetOptin,
        address owner,
        uint48 epochDuration,
        uint48 slashingWindow,
        address reader
    ) public initializer {
        if (owner == address(0) || reader == address(0)) {
            revert Middleware__InvalidAddress();
        }
        if (slashingWindow < epochDuration) {
            revert Middleware__SlashingWindowTooShort();
        }

        __BaseMiddleware_init(network, slashingWindow, vaultRegistry, operatorRegistry, operatorNetOptin, reader);
        __OzAccessControl_init(owner);
        __EpochCapture_init(epochDuration);
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, owner);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override checkAccess {}

    /**
     * @inheritdoc OSharedVaults
     */
    function _beforeRegisterSharedVault(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) internal virtual override {
        address stakerRewards =
            IODefaultStakerRewardsFactory(i_stakerRewardsFactory).create(sharedVault, stakerRewardsParams);

        IODefaultOperatorRewards(i_operatorRewards).setStakerRewardContract(stakerRewards, sharedVault);
    }

    // TODO: this should probably take into account underlying asset price and return a power which could be either the total value of the stake in usd or a value that makes sense for us
    function stakeToPower(address vault, uint256 stake) public view override returns (uint256 power) {
        return stake;
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function setGateway(
        address _gateway
    ) external checkAccess {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        $.gateway = IOGateway(_gateway);
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function setOperatorShareOnOperatorRewards(
        uint48 operatorShare
    ) external checkAccess {
        IODefaultOperatorRewards(i_operatorRewards).setOperatorShare(operatorShare);
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function distributeRewards(
        uint256 epoch,
        uint256 eraIndex,
        uint256 totalPointsToken,
        uint256 tokensInflatedToken,
        bytes32 rewardsRoot,
        address tokenAddress
    ) external onlyGateway {
        if (IERC20(tokenAddress).balanceOf(address(this)) < tokensInflatedToken) {
            revert Middleware__InsufficientBalance();
        }

        IERC20(tokenAddress).approve(i_operatorRewards, tokensInflatedToken);

        IODefaultOperatorRewards(i_operatorRewards).distributeRewards(
            uint48(epoch), uint48(eraIndex), tokensInflatedToken, totalPointsToken, rewardsRoot, tokenAddress
        );
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    //  TODO: this function should be split to allow to be called by chainlink in case
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory sortedKeys) {
        if (address(getGateway()) == address(0)) {
            revert Middleware__GatewayNotSet();
        }

        uint48 epoch = getCurrentEpoch();
        sortedKeys = sortOperatorsByVaults(epoch);

        getGateway().sendOperatorsData(sortedKeys, epoch);
    }

    function calcAndCacheStakes(
        uint48 epoch
    ) public returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStart(epoch);
        StorageMiddleware storage $ = _getMiddlewareStorage();

        // for epoch older than SLASHING_WINDOW total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - _SLASHING_WINDOW()) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }
        address[] memory _operators = _activeOperatorsAt(epochStartTs);

        uint256 operatorLength = _operators.length;
        for (uint256 i; i < operatorLength; ++i) {
            address operator = _operators[i];

            uint256 operatorStake = getOperatorStake(operator, epoch);
            $.operatorStakeCache[epoch][operator] = operatorStake;
            totalStake += operatorStake;
        }

        $.totalStakeIsCached[epoch] = true;
        $.totalStakeCache[epoch] = totalStake;
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    //TODO use prebuilt function from SDK
    function slash(
        uint48 epoch,
        bytes32 operatorKey,
        uint256 percentage
    ) external onlyGateway updateStakeCache(epoch) {
        uint48 epochStartTs = getEpochStart(epoch);
        address operator = operatorByKey(abi.encode(operatorKey));

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

        address[] memory vaults = _activeVaultsAt(epochStartTs, operator);
        // simple pro-rata slasher
        uint256 vaultsLength = vaults.length;
        for (uint256 i; i < vaultsLength; ++i) {
            _processVaultSlashing(vaults[i], params);
        }
    }

    /**
     * @dev Get vault stake and calculate slashing amount.
     * @param vault The vault address to calculate its stake
     * @param params Struct containing slashing parameters
     */
    function _processVaultSlashing(address vault, SlashParams memory params) private {
        for (uint96 j = 0; j < _subnetworksLength(); ++j) {
            bytes32 subnetwork = _NETWORK().subnetwork(j);
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

    function _beforeUnregisterOperator(
        address operator
    ) internal override {
        _updateKey(operator, abi.encode(bytes32(0)));
    }

    // **************************************************************************************************
    //                                      VIEW FUNCTIONS
    // **************************************************************************************************

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory activeOperators) {
        uint48 epochStartTs = getEpochStart(epoch);
        activeOperators = _activeOperatorsAt(epochStartTs);
    }

    /**
     * @dev Sorts operators by their total stake in descending order, after 500 it will be almost impossible to be used on-chain since 500 ≈ 36M gas
     * @param epoch The epoch number
     * @return sortedKeys Array of sorted operators keys based on their stake
     */
    function sortOperatorsByVaults(
        uint48 epoch
    ) public view returns (bytes32[] memory sortedKeys) {
        ValidatorData[] memory validatorSet = getValidatorSet(epoch);
        if (validatorSet.length == 0) {
            return sortedKeys;
        }
        validatorSet = validatorSet.quickSort(0, int256(validatorSet.length - 1));

        sortedKeys = new bytes32[](validatorSet.length);
        uint256 validatorSetLength = validatorSet.length;
        for (uint256 i; i < validatorSetLength; ++i) {
            sortedKeys[i] = validatorSet[i].key;
        }
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (OperatorVaultPair[] memory operatorVaultPairs) {
        uint48 epochStartTs = getEpochStart(epoch);
        address[] memory operators = _activeOperatorsAt(epochStartTs);

        operatorVaultPairs = new OperatorVaultPair[](operators.length);

        uint256 valIdx = 0;
        uint256 operatorsLength = operators.length;
        for (uint256 i; i < operatorsLength; ++i) {
            address operator = operators[i];
            (uint256 vaultIdx, address[] memory _vaults) = getOperatorVaults(operator, epochStartTs);
            assembly {
                mstore(_vaults, vaultIdx)
            }
            if (vaultIdx > 0) {
                operatorVaultPairs[valIdx++] = OperatorVaultPair(operator, _vaults);
            }
        }
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) public view returns (uint256 vaultIdx, address[] memory vaults) {
        address[] memory operatorVaults = _activeVaultsAt(epochStartTs, operator);
        vaults = new address[](operatorVaults.length);
        vaultIdx = 0;
        uint256 operatorVaultsLength = operatorVaults.length;
        for (uint256 j; j < operatorVaultsLength; ++j) {
            uint256 operatorStake = 0;
            address _vault = operatorVaults[j];
            for (uint96 k = 0; k < _subnetworksLength(); ++k) {
                operatorStake += IBaseDelegator(IVault(_vault).delegator()).stakeAt(
                    _NETWORK().subnetwork(k), operator, epochStartTs, new bytes(0)
                );
            }

            if (operatorStake > 0) {
                vaults[vaultIdx++] = _vault;
            }
        }
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function isVaultRegistered(
        address vault
    ) external view returns (bool) {
        VaultManagerStorage storage $ = _getVaultManagerStorage();
        return $._sharedVaults.contains(vault);
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getOperatorStake(address operator, uint48 epoch) public view returns (uint256 power) {
        if (totalStakeIsCached(epoch)) {
            return operatorStakeCache(epoch, operator);
        }
        uint48 epochStartTs = getEpochStart(epoch);
        power = _getOperatorPowerAt(epochStartTs, operator);
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getTotalStake(
        uint48 epoch
    ) public view returns (uint256) {
        if (totalStakeIsCached(epoch)) {
            return totalStakeCache(epoch);
        }
        return _calcTotalStake(epoch);
    }

    /**
     * @notice Gets an operator's active key at the current capture timestamp
     * @param operator The operator address to lookup
     * @return The operator's active key encoded as bytes, or encoded zero bytes if none
     */
    // TODO use this function where it's needed
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

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getValidatorSet(
        uint48 epoch
    ) public view returns (ValidatorData[] memory validatorSet) {
        uint48 epochStartTs = getEpochStart(epoch);
        address[] memory operators = _activeOperatorsAt(epochStartTs);

        validatorSet = new ValidatorData[](operators.length);
        uint256 len = 0;
        uint256 operatorsLength = operators.length;
        for (uint256 i; i < operatorsLength; ++i) {
            address operator = operators[i];

            bytes32 key = abi.decode(operatorKey(operator), (bytes32));
            if (key == bytes32(0) || !keyWasActiveAt(epochStartTs, abi.encode(key))) {
                continue;
            }

            uint256 power = _getOperatorPowerAt(epochStartTs, operator);

            validatorSet[len++] = ValidatorData(power, key);
        }

        // shrink array to skip unused slots
        assembly ("memory-safe") {
            mstore(validatorSet, len)
        }
    }

    // /**
    //  * @inheritdoc IMiddleware
    //  */
    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        EpochCaptureStorage storage $ = _getEpochCaptureStorage();
        return (timestamp - $.startTimestamp) / $.epochDuration;
    }

    /**
     * @dev Calculates total stake for an epoch
     * @param epoch The epoch to calculate stake for
     * @return totalStake The total stake amount
     */
    function _calcTotalStake(
        uint48 epoch
    ) private view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStart(epoch);
        // for epoch older than _SLASHING_WINDOW total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - _SLASHING_WINDOW()) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }
        address[] memory operators = _activeOperatorsAt(epochStartTs);
        uint256 operatorsLength = operators.length;
        for (uint256 i; i < operatorsLength; ++i) {
            uint256 operatorStake = getOperatorStake(operators[i], epoch);
            totalStake += operatorStake;
        }
    }
}
