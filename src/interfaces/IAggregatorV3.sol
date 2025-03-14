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

pragma solidity ^0.8.0;

interface IAggregatorV3 {
    function decimals() external view returns (uint8);

    /* @notice get data about the latest round. Consumers are encouraged to check
    * that they're receiving fresh data by inspecting the updatedAt and
    * answeredInRound return values.
    * Note that different underlying implementations of AggregatorV3Interface
    * have slightly different semantics for some of the return values. Consumers
    * should determine what implementations they expect to receive
    * data from and validate that they can properly handle return data from all
    * of them.
    * @return roundId is the round ID from the aggregator for which the data was
    * retrieved combined with an phase to ensure that round IDs get larger as
    * time moves forward.
    * @return answer is the answer for the given round
    * @return startedAt is the timestamp when the round was started.
    * (Only some AggregatorV3Interface implementations return meaningful values)
    * @return updatedAt is the timestamp when the round last was updated (i.e.
    * answer was last computed)
    * @return answeredInRound is the round ID of the round in which the answer
    * was computed.
    * (Only some AggregatorV3Interface implementations return meaningful values)
    * @dev Note that answer and updatedAt may change between queries.
    */
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
