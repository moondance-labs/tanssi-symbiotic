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

    error AggregatorV3Proxy__InvalidData();

    constructor(address _aggregator, string memory _pairSymbol) {
        if (_aggregator == address(0) || bytes(_pairSymbol).length == 0) {
            revert AggregatorV3Proxy__InvalidData();
        }
        aggregator = IDIAOracleV2(_aggregator);
        pairSymbol = _pairSymbol;
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
    ) external view override returns (uint80, int256, uint256, uint256, uint80) {
        (uint128 latestPrice, uint128 timestampOfLatestPrice) = aggregator.getValue(pairSymbol);

        return (
            uint80(1),
            int256(uint256(latestPrice)),
            uint256(timestampOfLatestPrice),
            uint256(timestampOfLatestPrice),
            uint80(1)
        );
    }

    function latestRoundData() external view override returns (uint80, int256, uint256, uint256, uint80) {
        (uint128 latestPrice, uint128 timestampOfLatestPrice) = aggregator.getValue(pairSymbol);

        return (
            uint80(1),
            int256(uint256(latestPrice)),
            uint256(timestampOfLatestPrice),
            uint256(timestampOfLatestPrice),
            uint80(1)
        );
    }
}
