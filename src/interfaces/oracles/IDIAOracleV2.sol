pragma solidity 0.8.25;

interface IDIAOracleV2 {
    function getValue(
        string memory
    ) external view returns (uint128 latestPrice, uint128 timestampOfLatestPrice);
}
