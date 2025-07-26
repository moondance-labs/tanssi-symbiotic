pragma solidity 0.8.25;

contract DIAOracleMock {
    struct Price {
        uint128 latestPrice;
        uint128 timestampOfLatestPrice;
    }

    mapping(string => Price) private prices;

    constructor(string memory pairSymbol, uint128 latestPrice, uint128 timestampOfLatestPrice) {
        prices[pairSymbol] = Price(latestPrice, timestampOfLatestPrice);
    }

    function setValue(uint128 latestPrice, uint128 timestampOfLatestPrice, string memory pairSymbol) external {
        prices[pairSymbol] = Price(latestPrice, timestampOfLatestPrice);
    }

    function getValue(
        string memory pairSymbol
    ) external view returns (uint128 latestPrice, uint128 timestampOfLatestPrice) {
        Price storage price = prices[pairSymbol];
        return (price.latestPrice, price.timestampOfLatestPrice);
    }
}
