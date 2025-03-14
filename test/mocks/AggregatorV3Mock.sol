// SPDX-License-Identifier: GPL-3.0-or-later
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

import {IAggregatorV3} from "src/interfaces/IAggregatorV3.sol";

// TODO: Use mock from chainlink
contract AggregatorV3Mock is IAggregatorV3 {
    uint8 public decimals;
    int256 private _answer;

    constructor(
        uint8 _decimals
    ) {
        decimals = _decimals;
    }

    function setAnswer(
        int256 answer
    ) external {
        _answer = answer;
    }

    function latestRoundData() external view returns (uint80, int256 answer, uint256, uint256, uint80) {
        return (0, _answer, 0, 0, 0);
    }
}
