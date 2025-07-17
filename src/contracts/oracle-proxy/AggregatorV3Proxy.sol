// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

//**************************************************************************************************
//                                      CHAINLINK
//**************************************************************************************************
import {AggregatorV3Interface} from "@chainlink/shared/interfaces/AggregatorV2V3Interface.sol";

import {IDIAOracleV2} from "src/interfaces/oracles/IDIAOracleV2.sol";

contract AggregatorV3Proxy is AggregatorV3Interface {
    string public pairSymbol;
    IDIAOracleV2 public aggregator;

    constructor(address _aggregator, string memory _pairSymbol) {
        pairSymbol = pairSymbol;
        aggregator = IDIAOracleV2(_aggregator);
    }

    function decimals() external pure override returns (uint8) {
        return 8;
    }

    function description() external view override returns (string memory) {
        return pairSymbol;
    }

    function version() external pure override returns (uint256) {
        return 1;
    }

    function getRoundData(
        uint80 /*_roundId*/
    )
        external
        view
        override
        returns (uint80 roundId, int256 ans, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        (uint128 latestPrice, uint128 timestampOfLatestPrice) = aggregator.getValue(pairSymbol);
        int256 answer = int256(uint256(latestPrice));

        return (uint80(1), answer, uint256(timestampOfLatestPrice), uint256(timestampOfLatestPrice), uint80(1));
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80 roundId, int256 ans, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        (uint128 latestPrice, uint128 timestampOfLatestPrice) = aggregator.getValue(pairSymbol);

        int256 answer = int256(uint256(latestPrice));

        return (uint80(1), answer, uint256(timestampOfLatestPrice), uint256(timestampOfLatestPrice), uint80(1));
    }
}
