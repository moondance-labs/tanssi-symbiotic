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

import {IMiddleware} from "src/interfaces/middleware/IMiddleware.sol";

interface IOBaseMiddlewareReader {
    function getCaptureTimestamp() external view returns (uint48 timestamp);

    function stakeToPower(address vault, uint256 stake) external view returns (uint256 power);

    function keyWasActiveAt(uint48 timestamp, bytes memory key) external view returns (bool);

    function operatorKey(
        address operator
    ) external view returns (bytes memory);

    function operatorByKey(
        bytes memory key
    ) external view returns (address);

    function getEpochStart(
        uint48 epoch
    ) external view returns (uint48);

    function getCurrentEpoch() external view returns (uint48);

    function getEpochDuration() external view returns (uint48);

    function NETWORK() external view returns (address);

    function SLASHING_WINDOW() external view returns (uint48);

    function VAULT_REGISTRY() external view returns (address);

    function OPERATOR_REGISTRY() external view returns (address);

    function OPERATOR_NET_OPTIN() external view returns (address);

    function operatorsLength() external view returns (uint256);

    function operatorWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48);

    function activeOperators() external view returns (address[] memory);

    function activeOperatorsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function operatorWasActiveAt(uint48 timestamp, address operator) external view returns (bool);

    function isOperatorRegistered(
        address operator
    ) external view returns (bool);

    function subnetworksLength() external view returns (uint256);

    function subnetworkWithTimesAt(
        uint256 pos
    ) external view returns (uint160, uint48, uint48);

    function activeSubnetworks() external view returns (uint160[] memory);

    function activeSubnetworksAt(
        uint48 timestamp
    ) external view returns (uint160[] memory);

    function subnetworkWasActiveAt(uint48 timestamp, uint96 subnetwork) external view returns (bool);

    function sharedVaultsLength() external view returns (uint256);

    function sharedVaultWithTimesAt(
        uint256 pos
    ) external view returns (address, uint48, uint48);

    function activeSharedVaults() external view returns (address[] memory);

    function activeSharedVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function operatorVaultsLength(
        address operator
    ) external view returns (uint256);

    function operatorVaultWithTimesAt(address operator, uint256 pos) external view returns (address, uint48, uint48);

    function activeOperatorVaults(
        address operator
    ) external view returns (address[] memory);

    function activeOperatorVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory);

    function activeVaults() external view returns (address[] memory);

    function activeVaultsAt(
        uint48 timestamp
    ) external view returns (address[] memory);

    function activeVaults(
        address operator
    ) external view returns (address[] memory);

    function activeVaultsAt(uint48 timestamp, address operator) external view returns (address[] memory);

    function vaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool);

    function sharedVaultWasActiveAt(uint48 timestamp, address vault) external view returns (bool);

    function operatorVaultWasActiveAt(uint48 timestamp, address operator, address vault) external view returns (bool);

    function getOperatorPower(address operator, address vault, uint96 subnetwork) external view returns (uint256);

    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address vault,
        uint96 subnetwork
    ) external view returns (uint256);

    function getOperatorPower(
        address operator
    ) external view returns (uint256);

    function getOperatorPowerAt(uint48 timestamp, address operator) external view returns (uint256);

    function getOperatorPower(
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256);

    function getOperatorPowerAt(
        uint48 timestamp,
        address operator,
        address[] memory vaults,
        uint160[] memory subnetworks
    ) external view returns (uint256);

    function totalPower(
        address[] memory operators
    ) external view returns (uint256);

    function getOperatorsByEpoch(
        uint48 epoch
    ) external view returns (address[] memory activeOperators_);

    function getOperatorVaultPairs(
        uint48 epoch
    ) external view returns (IMiddleware.OperatorVaultPair[] memory operatorVaultPairs);

    function isVaultRegistered(
        address vault
    ) external view returns (bool);

    function sortOperatorsByPower(
        uint48 epoch
    ) external view returns (bytes32[] memory sortedKeys);

    function sortOperatorsByPower(
        IMiddleware.ValidatorData[] memory validatorSet
    ) external view returns (bytes32[] memory sortedKeys);

    function getOperatorVaults(
        address operator,
        uint48 epochStartTs
    ) external view returns (uint256 vaultIdx, address[] memory _vaults);

    function getTotalStake(
        uint48 epoch
    ) external view returns (uint256);

    function getOperatorKeyAt(address operator, uint48 timestamp) external view returns (bytes memory);

    function getValidatorSet(
        uint48 epoch
    ) external view returns (IMiddleware.ValidatorData[] memory validatorsData);

    function getEpochAtTs(
        uint48 timestamp
    ) external view returns (uint48 epoch);

    function auxiliaryCheckUpkeep() external view returns (bool upkeepNeeded, bytes memory performData);

    function checkTotalActiveVaults(
        address operator
    ) external view;
}
