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

import {Test} from "forge-std/Test.sol";
import {DIAOracleMock} from "test/mocks/DIAOracleMock.sol";
import {AggregatorV3DIAProxy} from "src/contracts/oracle-proxy/AggregatorV3DIAProxy.sol";
import {Token} from "../mocks/Token.sol";

contract MiddlewareTest is Test {
    int256 public constant ORACLE_CONVERSION_TANSSI = 1 * 10 ** 8;
    string public constant TANSSI_PAIR_SYMBOL = "TANSSI/USD";

    Token tanssiCollateral;
    DIAOracleMock diaOracle;
    AggregatorV3DIAProxy tanssiCollateralOracle;

    function setUp() public {
        tanssiCollateral = new Token("TANSSI", 12);

        diaOracle = new DIAOracleMock(
            TANSSI_PAIR_SYMBOL, uint128(uint256(ORACLE_CONVERSION_TANSSI)), uint128(vm.getBlockTimestamp())
        );

        tanssiCollateralOracle = new AggregatorV3DIAProxy(address(diaOracle), TANSSI_PAIR_SYMBOL);
    }

    function testDIAGetValueTanssiPrice() public view {
        (uint128 latestPrice, uint128 latestTimestamp) = diaOracle.getValue(TANSSI_PAIR_SYMBOL);
        assertEq(latestPrice, uint128(uint256(ORACLE_CONVERSION_TANSSI)));
        assertEq(latestTimestamp, uint128(vm.getBlockTimestamp()));
    }

    function testDIASetValueForeignTokenPrice() public {
        uint128 newPrice = 2 * uint128(uint256(ORACLE_CONVERSION_TANSSI));
        uint128 newTimestamp = uint128(vm.getBlockTimestamp() + 1000);
        diaOracle.setValue(newPrice, newTimestamp, TANSSI_PAIR_SYMBOL);

        (uint128 latestPrice, uint128 latestTimestamp) = diaOracle.getValue(TANSSI_PAIR_SYMBOL);
        assertEq(latestPrice, newPrice);
        assertEq(latestTimestamp, newTimestamp);
    }

    function testAggregatorV3DIAProxyDecimals() public view {
        uint8 decimals = tanssiCollateralOracle.decimals();
        assertEq(decimals, 8);
    }

    function testAggregatorV3DIAProxyDescription() public view {
        string memory description = tanssiCollateralOracle.description();
        assertEq(description, TANSSI_PAIR_SYMBOL);
    }

    function testAggregatorV3DIAProxyVersion() public view {
        uint256 version = tanssiCollateralOracle.version();
        assertEq(version, 1);
    }

    function testAggregatorV3DIAProxyGetRoundData() public view {
        (uint80 roundId, int256 price, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            tanssiCollateralOracle.getRoundData(1);

        assertEq(roundId, 1);
        assertEq(price, int256(uint256(ORACLE_CONVERSION_TANSSI)));
        assertEq(startedAt, vm.getBlockTimestamp());
        assertEq(updatedAt, vm.getBlockTimestamp());
        assertEq(answeredInRound, 1);
    }

    function testAggregatorV3DIAProxyLatestRoundData() public view {
        (uint80 roundId, int256 price, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            tanssiCollateralOracle.latestRoundData();

        assertEq(roundId, 1);
        assertEq(price, int256(uint256(ORACLE_CONVERSION_TANSSI)));
        assertEq(startedAt, vm.getBlockTimestamp());
        assertEq(updatedAt, vm.getBlockTimestamp());
        assertEq(answeredInRound, 1);
    }

    function testAggregatorV3DIAProxyInvalidAggregatorAddress() public {
        vm.expectRevert(AggregatorV3DIAProxy.AggregatorV3DIAProxy__InvalidData.selector);
        new AggregatorV3DIAProxy(address(0), TANSSI_PAIR_SYMBOL);
    }

    function testAggregatorV3DIAProxyInvalidPairSymbol() public {
        vm.expectRevert(AggregatorV3DIAProxy.AggregatorV3DIAProxy__InvalidData.selector);
        new AggregatorV3DIAProxy(address(diaOracle), "");
    }
}
