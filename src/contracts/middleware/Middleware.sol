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
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

//**************************************************************************************************
//                                      SYMBIOTIC
//**************************************************************************************************
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
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

//**************************************************************************************************
//                                      TANSSI META MIDDLEWARE
//**************************************************************************************************
import {ITanssiCommonMiddleware} from "@tanssi-meta-middleware/interfaces/ITanssiCommonMiddleware.sol";
import {ITanssiMetaMiddleware} from "@tanssi-meta-middleware/interfaces/ITanssiMetaMiddleware.sol";

//**************************************************************************************************
//                                      TANSSI
//**************************************************************************************************
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
    IMiddleware,
    ITanssiCommonMiddleware
{
    using Subnetwork for address;
    using Math for uint256;
    using SafeERC20 for IERC20;

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
     */
    function initialize(
        InitParams memory params
    ) external initializer {
        _validateInitParams(params);

        {
            MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
            $.lastTimestamp = Time.timestamp();
            $.interval = params.epochDuration;
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
    }

    /*
     * @notice Reinitialize the middleware with only operator rewards and staker rewards factory addresses
     * @param operatorRewards The operator rewards address
     * @param stakerRewardsFactory The staker rewards factory address
     */
    function reinitializeRewards(
        address operatorRewards,
        address stakerRewardsFactory
    ) external reinitializer(3) notZeroAddress(operatorRewards) notZeroAddress(stakerRewardsFactory) {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        $.i_operatorRewards = operatorRewards;
        $.i_stakerRewardsFactory = stakerRewardsFactory;
    }

    /*
     * @notice Reinitialize to set the onReport selector role
     */
    function reinitializeMetaMiddleware(
        address metaMiddleware
    ) external reinitializer(4) notZeroAddress(metaMiddleware) {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        $.i_metaMiddleware = ITanssiMetaMiddleware(metaMiddleware);
        _grantRole(MiddlewareStorage.META_MIDDLEWARE_ROLE, metaMiddleware);

        _setSelectorRole(this.distributeRewards.selector, MiddlewareStorage.META_MIDDLEWARE_ROLE);
        _setSelectorRole(this.transferRewards.selector, MiddlewareStorage.META_MIDDLEWARE_ROLE);
        _setSelectorRole(this.slash.selector, MiddlewareStorage.META_MIDDLEWARE_ROLE);
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
    {
        if (params.epochDuration == 0 || params.slashingWindow == 0) {
            revert Middleware__InvalidEpochDuration();
        }

        if (params.slashingWindow < params.epochDuration) {
            revert Middleware__SlashingWindowTooShort();
        }
    }

    function stakeToPower(address vault, uint256 stake) public view override returns (uint256 power) {
        return IOBaseMiddlewareReader(address(this)).getPowerInUSD(vault, stake);
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
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();

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
        //TODO !!! TO CHECK PROBABLY WE COULD TAKE OUT FROM STORAGE THE ADDRESS
        // WE DIRECTLY CHECK THAT THE ADDRESS HAS THE ROLE. THERE IS NO POINT IN STORING IT
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        address currentForwarderAddress = $.forwarderAddress;
        if (forwarder == currentForwarderAddress) {
            revert Middleware__AlreadySet();
        }

        $.forwarderAddress = forwarder;
        _revokeRole(MiddlewareStorage.FORWARDER_ROLE, currentForwarderAddress);
        _grantRole(MiddlewareStorage.FORWARDER_ROLE, forwarder);

        emit ForwarderSet(forwarder);
    }

    /**
     * @inheritdoc IMiddleware
     */
    function setOperatorShareOnOperatorRewards(
        uint48 operatorShare
    ) external checkAccess {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        IODefaultOperatorRewards($.i_operatorRewards).setOperatorShare(operatorShare);
    }

    /**
     * @inheritdoc ITanssiCommonMiddleware
     */
    function slash(uint48 epoch, address operator, uint256 percentage) external checkAccess {
        uint48 epochStartTs = IOBaseMiddlewareReader(address(this)).getEpochStart(epoch);

        if (epochStartTs + _SLASHING_WINDOW() < Time.timestamp()) {
            revert Middleware__TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert Middleware__InvalidEpoch();
        }

        // Sanitization: check percentage is below 100% (or 1 billion in other words)
        if (percentage > PARTS_PER_BILLION) {
            revert Middleware__SlashPercentageTooBig(epoch, operator, percentage);
        }

        _slash(epochStartTs, operator, percentage);
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
        bytes32 ReaderStorageLocation_ = 0xfd87879bc98f37af7578af722aecfbe5843e5ad354da2d1e70cb5157c4ec8800;
        assembly {
            sstore(ReaderStorageLocation_, reader)
        }
    }

    /**
     * @inheritdoc ITanssiCommonMiddleware
     */
    function prepareRewardsDistributionData(
        uint48 eraIndex,
        address rewardsToken
    ) external view returns (bytes memory rewardsDistributionData) {
        rewardsDistributionData = new bytes(0);
    }

    /**
     * @inheritdoc ITanssiCommonMiddleware
     */
    function prepareRewardsDistributionDataFromOperatorRewards(
        uint48 eraIndex,
        address rewardsToken,
        ITanssiMetaMiddleware.OperatorReward[] memory operatorRewards
    ) external view returns (bytes memory rewardsDistributionData) {
        rewardsDistributionData = new bytes(0);
    }

    /**
     * @inheritdoc ITanssiCommonMiddleware
     */
    function distributeRewards(
        uint48 eraIndex,
        address tokenAddress,
        bytes memory /* rewardsDistributionData */
    ) external returns (bool distributionComplete) {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        ITanssiMetaMiddleware.EraRoot memory eraRoot = $.i_metaMiddleware.getEraRoot(eraIndex);

        uint256 tokenAmount = eraRoot.totalAmount;

        if (IERC20(tokenAddress).balanceOf(address(this)) < tokenAmount) {
            revert Middleware__InsufficientBalance();
        }

        IERC20(tokenAddress).approve($.i_operatorRewards, tokenAmount);

        IODefaultOperatorRewards($.i_operatorRewards).distributeRewards(
            eraRoot.epoch, eraIndex, tokenAmount, eraRoot.totalPoints, eraRoot.root, tokenAddress
        );

        distributionComplete = true;
    }

    function activeOperatorsAtEpoch(
        uint48 epoch
    ) external view returns (address[] memory) {
        uint48 epochStartTs = getEpochStart(epoch);
        return _activeOperatorsAt(epochStartTs);
    }

    function getMetaMiddleware() external view returns (address) {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        return address($.i_metaMiddleware);
    }

    function transferRewards(uint48 eraIndex, address tokenAddress, uint256 totalRewards) external {
        // TODO migration: complete implementation
        // MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        // if ($.rewardsPerEra[eraIndex][tokenAddress] != 0) {
        //     revert Middleware__RewardsAlreadyTransferredForEra();
        // }
        // $.rewardsPerEra[eraIndex][tokenAddress] = totalRewards;
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), totalRewards);
    }

    /**
     * @inheritdoc OSharedVaults
     */
    function _afterRegisterSharedVault(
        address sharedVault,
        IODefaultStakerRewards.InitParams memory stakerRewardsParams
    ) internal override {
        if (_sharedVaultsLength() >= MiddlewareStorage.MAX_ACTIVE_VAULTS) {
            revert Middleware__TooManyActiveVaults();
        }

        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        address stakerRewards =
            IODefaultStakerRewardsFactory($.i_stakerRewardsFactory).create(sharedVault, stakerRewardsParams);

        IODefaultOperatorRewards($.i_operatorRewards).setStakerRewardContract(stakerRewards, sharedVault);

        MiddlewareStorage.setVaultToCollateral(sharedVault);
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeRegisterOperatorVault(
        address,
        /* operator */
        address vault
    ) internal override {
        MiddlewareStorage.setVaultToCollateral(vault);
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeRegisterOperator(
        address operator,
        bytes memory key,
        address
    ) internal override notZeroAddress(operator) {
        // TODO Migration: This might be not needed anymore since it's decoded later
        if (key.length != 32 || abi.decode(key, (bytes32)) == bytes32(0)) {
            revert Middleware__InvalidKey();
        }

        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        ITanssiMetaMiddleware($.i_metaMiddleware).registerOperator(operator, abi.decode(key, (bytes32)));
    }

    function _beforeUpdateOperatorKey(address operator, bytes memory key) internal override {
        MiddlewareStorage.StorageMiddleware storage $ = MiddlewareStorage.getMiddlewareStorage();
        // TODO migration: This should happen when updateOperatorKey is called, but the hooks is also called when registering an operator, so it would run twice and revert. Needs to be fixed.
        // ITanssiMetaMiddleware($.i_metaMiddleware).updateOperatorKey(operator, abi.decode(key, (bytes32)));
    }

    /**
     * @inheritdoc BaseOperators
     */
    function _beforeUnregisterOperator(
        address operator
    ) internal override {
        // TODO Migration: Is it safe to update the key to 0, shall we also do it on meta middleware? Should other middlewares also do this?
        _updateKey(operator, abi.encode(bytes32(0)));
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
