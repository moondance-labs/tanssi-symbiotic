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
import {AutomationCompatibleInterface} from "@chainlink/automation/interfaces/AutomationCompatibleInterface.sol";
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

//**************************************************************************************************
//                                      OPENZEPPELIN
//**************************************************************************************************
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

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
import {BaseOperators} from "@symbiotic-middleware/extensions/operators/BaseOperators.sol";
import {KeyManager256} from "@symbiotic-middleware/extensions/managers/keys/KeyManager256.sol";
import {OzAccessControl} from "@symbiotic-middleware/extensions/managers/access/OzAccessControl.sol";
import {EpochCapture} from "@symbiotic-middleware/extensions/managers/capture-timestamps/EpochCapture.sol";
import {VaultManager} from "@symbiotic-middleware/managers/VaultManager.sol";
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

import {IOBaseMiddlewareReader} from "src/interfaces/middleware/IOBaseMiddlewareReader.sol";

contract Middleware is
    UUPSUpgradeable,
    OSharedVaults,
    Operators,
    KeyManager256,
    OzAccessControl,
    EpochCapture,
    AutomationCompatibleInterface,
    MiddlewareStorage,
    IMiddleware
{
    using PauseableEnumerableSet for PauseableEnumerableSet.AddressSet;
    using PauseableEnumerableSet for PauseableEnumerableSet.Status;
    using Subnetwork for address;
    using Subnetwork for bytes32;
    using Math for uint256;

    modifier notZeroAddress(
        address address_
    ) {
        _checkNotZeroAddress(address_);
        _;
    }

    /*
     * @notice Constructor for the middleware
     */
    constructor() {
        _disableInitializers();
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
     * @param operatorRewards The operator rewards address
     * @param stakerRewardsFactory The staker rewards factory address
     */
    function initialize(
        InitParams memory params
    ) external initializer {
        _validateInitParams(params);

        {
            StorageMiddleware storage $ = _getMiddlewareStorage();
            $.lastTimestamp = Time.timestamp();
            $.interval = params.epochDuration;
            i_operatorRewards = params.operatorRewards;
            i_stakerRewardsFactory = params.stakerRewardsFactory;
        }

        __BaseMiddleware_init(
            params.network,
            params.slashingWindow,
            params.vaultRegistry,
            params.operatorRegistry,
            params.operatorNetworkOptIn,
            params.reader
        );
        __OzAccessControl_init(params.owner);
        __EpochCapture_init(params.epochDuration);
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, params.owner);
        _setSelectorRole(this.distributeRewards.selector, GATEWAY_ROLE);
        _setSelectorRole(this.slash.selector, GATEWAY_ROLE);
        _setSelectorRole(this.performUpkeep.selector, FORWARDER_ROLE);
    }

    /*
     * @notice Reinitialize the middleware with only operator rewards and staker rewards factory addresses
     * @param operatorRewards The operator rewards address
     * @param stakerRewardsFactory The staker rewards factory address
     */
    function reinitializeRewards(
        address operatorRewards,
        address stakerRewardsFactory
    ) external reinitializer(2) notZeroAddress(operatorRewards) notZeroAddress(stakerRewardsFactory) {
        i_operatorRewards = operatorRewards;
        i_stakerRewardsFactory = stakerRewardsFactory;
    }

    function _validateInitParams(
        InitParams memory params
    )
        private
        pure
        notZeroAddress(params.network)
        notZeroAddress(params.operatorRegistry)
        notZeroAddress(params.vaultRegistry)
        notZeroAddress(params.operatorNetworkOptIn)
        notZeroAddress(params.owner)
        notZeroAddress(params.reader)
        notZeroAddress(params.operatorRewards)
        notZeroAddress(params.stakerRewardsFactory)
    {
        if (params.epochDuration == 0 || params.slashingWindow == 0) {
            revert Middleware__InvalidEpochDuration();
        }

        if (params.slashingWindow < params.epochDuration) {
            revert Middleware__SlashingWindowTooShort();
        }
    }

    function stakeToPower(address vault, uint256 stake) public view override returns (uint256 power) {
        address collateral = vaultToCollateral(vault);
        address oracle = collateralToOracle(collateral);

        if (oracle == address(0)) {
            revert Middleware__NotSupportedCollateral(collateral);
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
     * @inheritdoc IMiddleware
     */
    function setGateway(
        address newGateway
    ) external checkAccess notZeroAddress(newGateway) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        address oldGateway = $.gateway;

        if (newGateway == oldGateway) {
            revert Middleware__AlreadySet();
        }

        $.gateway = newGateway;
        _revokeRole(GATEWAY_ROLE, oldGateway);
        _grantRole(GATEWAY_ROLE, newGateway);

        emit GatewaySet(newGateway);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function setInterval(
        uint256 interval
    ) external checkAccess {
        if (interval == 0) {
            revert Middleware__InvalidInterval();
        }
        StorageMiddleware storage $ = _getMiddlewareStorage();

        if (interval == $.interval) {
            revert Middleware__AlreadySet();
        }

        $.interval = interval;
        emit IntervalSet(interval);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function setForwarder(
        address forwarder
    ) external checkAccess notZeroAddress(forwarder) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        address currentForwarderAddress = $.forwarderAddress;
        if (forwarder == currentForwarderAddress) {
            revert Middleware__AlreadySet();
        }

        $.forwarderAddress = forwarder;
        _revokeRole(FORWARDER_ROLE, currentForwarderAddress);
        _grantRole(FORWARDER_ROLE, forwarder);

        emit ForwarderSet(forwarder);
    }

    function setCollateralToOracle(
        address collateral,
        address oracle
    ) external checkAccess notZeroAddress(collateral) {
        StorageMiddleware storage $ = _getMiddlewareStorage();

        // Oracle is not checked against zero so this can be used to remove the oracle from a collateral

        $.collateralToOracle[collateral] = oracle;
        emit CollateralToOracleSet(collateral, oracle);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function setOperatorShareOnOperatorRewards(
        uint48 operatorShare
    ) external checkAccess {
        IODefaultOperatorRewards(i_operatorRewards).setOperatorShare(operatorShare);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function distributeRewards(
        uint256 epoch,
        uint256 eraIndex,
        uint256 totalPoints,
        uint256 tokenAmount,
        bytes32 rewardsRoot,
        address tokenAddress
    ) external checkAccess {
        if (IERC20(tokenAddress).balanceOf(address(this)) < tokenAmount) {
            revert Middleware__InsufficientBalance();
        }

        IERC20(tokenAddress).approve(i_operatorRewards, tokenAmount);

        IODefaultOperatorRewards(i_operatorRewards).distributeRewards(
            uint48(epoch), uint48(eraIndex), tokenAmount, totalPoints, rewardsRoot, tokenAddress
        );
    }

    /**
     * @inheritdoc IMiddleware
     */
    function sendCurrentOperatorsKeys() external returns (bytes32[] memory sortedKeys) {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        if (block.number < $.lastExecutionBlock + MIN_INTERVAL_TO_SEND_OPERATOR_KEYS) {
            return sortedKeys;
        }

        address gateway = getGateway();
        if (gateway == address(0)) {
            revert Middleware__GatewayNotSet();
        }

        $.lastExecutionBlock = block.number;
        uint48 epoch = getCurrentEpoch();
        sortedKeys = IOBaseMiddlewareReader(address(this)).sortOperatorsByPower(epoch);
        IOGateway(gateway).sendOperatorsData(sortedKeys, epoch);
    }

    /**
     * @inheritdoc AutomationCompatibleInterface
     * @dev Called by chainlink nodes off-chain to check if the upkeep is needed
     * @return upkeepNeeded boolean to indicate whether the keeper should call performUpkeep or not.
     * @return performData bytes of the sorted (by power) operators' keys and the epoch that will be used by the keeper when calling performUpkeep, if upkeep is needed.
     */
    function checkUpkeep(
        bytes calldata /* checkData */
    ) external view override returns (bool upkeepNeeded, bytes memory performData) {
        (upkeepNeeded, performData) = IOBaseMiddlewareReader(address(this)).auxiliaryCheckUpkeep();
    }

    /**
     * @inheritdoc AutomationCompatibleInterface
     * @dev Called by chainlink nodes off-chain to perform the upkeep. It will send the sorted keys to the gateway
     */
    function performUpkeep(
        bytes calldata performData
    ) external override checkAccess {
        if (performData.length == 0) {
            revert Middleware__NoPerformData();
        }

        StorageMiddleware storage $ = _getMiddlewareStorage();
        address gateway = $.gateway;
        if (gateway == address(0)) {
            revert Middleware__GatewayNotSet();
        }

        uint48 epoch = getCurrentEpoch();
        StorageMiddlewareCache storage cache = _getMiddlewareStorageCache();

        address[] memory activeOperators = _activeOperators();
        uint256 activeOperatorsLength = activeOperators.length;
        uint256 cacheIndex = cache.epochToCacheIndex[epoch];
        uint256 pendingOperatorsToCache = activeOperatorsLength - cacheIndex;

        if (pendingOperatorsToCache > 0) {
            (uint8 command, ValidatorData[] memory validatorsData) = abi.decode(performData, (uint8, ValidatorData[]));

            if (command != CACHE_DATA_COMMAND) {
                revert Middleware__InvalidCommand(command);
            }

            uint256 validatorsDataLength = validatorsData.length;
            for (uint256 i = 0; i < validatorsDataLength;) {
                ValidatorData memory validatorData = validatorsData[i];
                bytes32 validatorKey = validatorData.key;
                // Update the cache with the operator power and the operator
                if (cache.operatorKeyToPower[epoch][validatorKey] != 0) {
                    revert Middleware__AlreadyCached();
                }

                cache.operatorKeyToPower[epoch][validatorKey] = validatorData.power;
                unchecked {
                    ++i;
                }
            }

            unchecked {
                cache.epochToCacheIndex[epoch] += validatorsDataLength;
            }
        } else {
            uint48 currentTimestamp = Time.timestamp();
            if ((currentTimestamp - $.lastTimestamp) > $.interval) {
                $.lastTimestamp = currentTimestamp;

                // Decode the sorted keys and the epoch from performData
                (uint8 command, bytes32[] memory sortedKeys) = abi.decode(performData, (uint8, bytes32[]));

                if (command != SEND_DATA_COMMAND) {
                    revert Middleware__InvalidCommand(command);
                }

                IOGateway(gateway).sendOperatorsData(sortedKeys, epoch);
            }
        }
    }

    /**
     * @inheritdoc IMiddleware
     */
    function slash(uint48 epoch, bytes32 operatorKey, uint256 percentage) external checkAccess {
        uint48 epochStartTs = IOBaseMiddlewareReader(address(this)).getEpochStart(epoch);
        address operator = operatorByKey(abi.encode(operatorKey));

        if (epochStartTs + _SLASHING_WINDOW() < Time.timestamp()) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }

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
        for (uint256 i; i < vaultsLength;) {
            _processVaultSlashing(vaults[i], params);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Execute a slash with a given slash index using hints.
     * @param vault The vault address, must have a veto slasher
     * @param slashIndex index of the slash request
     * @param hints hints for checkpoints' indexes
     * @return slashedAmount virtual amount of the collateral slashed
     */
    function executeSlash(
        address vault,
        uint256 slashIndex,
        bytes calldata hints
    ) external returns (uint256 slashedAmount) {
        slashedAmount = _executeSlash(vault, slashIndex, hints);
    }

    /**
     * @dev Set the reader address.
     * @param reader The MiddlewareReader address
     */
    function setReader(
        address reader
    ) external checkAccess notZeroAddress(reader) {
        // From BaseMiddleware.sol
        bytes32 ReaderStorageLocation = 0xfd87879bc98f37af7578af722aecfbe5843e5ad354da2d1e70cb5157c4ec8800;
        assembly {
            sstore(ReaderStorageLocation, reader)
        }
    }

    /**
     * @dev Get vault stake and calculate slashing amount.
     * @param vault The vault address to calculate its stake
     * @param params Struct containing slashing parameters
     */
    function _processVaultSlashing(address vault, SlashParams memory params) private {
        // Tanssi will use only one subnetwork so we only check the first
        bytes32 subnetwork = _NETWORK().subnetwork(0);

        uint256 vaultStake = IBaseDelegator(IVault(vault).delegator()).stakeAt(
            subnetwork, params.operator, params.epochStartTs, new bytes(0)
        );
        // Slash percentage is already in parts per billion
        // so we need to divide by a billion
        uint256 slashAmount = params.slashPercentage.mulDiv(vaultStake, PARTS_PER_BILLION);

        _slashVault(params.epochStartTs, vault, subnetwork, params.operator, slashAmount);
    }

    /**
     * @dev Slashes a vault's stake for a specific operator. Middleware SDK already provides _slashVault function but  custom version is needed to avoid revert in specific scenarios for the gateway message passing.
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

        uint256 response;
        if (slasherType == uint256(SlasherType.INSTANT)) {
            response = ISlasher(slasher).slash(subnetwork, operator, amount, timestamp, new bytes(0));
            emit VaultManager.InstantSlash(vault, subnetwork, response);
        } else if (slasherType == uint256(SlasherType.VETO)) {
            response = IVetoSlasher(slasher).requestSlash(subnetwork, operator, amount, timestamp, new bytes(0));
            emit VaultManager.VetoSlash(vault, subnetwork, response);
        } else {
            revert VaultManager.UnknownSlasherType();
        }
    }

    /**
     * @inheritdoc OSharedVaults
     */
    function _afterRegisterSharedVault(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) internal override {
        address stakerRewards =
            IODefaultStakerRewardsFactory(i_stakerRewardsFactory).create(sharedVault, stakerRewardsParams);

        IODefaultOperatorRewards(i_operatorRewards).setStakerRewardContract(stakerRewards, sharedVault);

        _setVaultToCollateral(sharedVault);
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeRegisterOperatorVault(address, /* operator */ address vault) internal override {
        _setVaultToCollateral(vault);
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeRegisterOperator(
        address operator,
        bytes memory key,
        address
    ) internal pure override notZeroAddress(operator) {
        if (abi.decode(key, (bytes32)) == bytes32(0)) {
            revert Middleware__InvalidKey();
        }
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeUnregisterOperator(
        address operator
    ) internal override {
        _updateKey(operator, abi.encode(bytes32(0)));
    }

    function _setVaultToCollateral(
        address vault
    ) private {
        StorageMiddleware storage $ = _getMiddlewareStorage();
        address collateral = IVault(vault).collateral();
        _checkNotZeroAddress(collateral);
        $.vaultToCollateral[vault] = collateral;
    }

    function _checkNotZeroAddress(
        address address_
    ) private pure {
        if (address_ == address(0)) {
            revert Middleware__InvalidAddress();
        }
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override checkAccess {}
}
