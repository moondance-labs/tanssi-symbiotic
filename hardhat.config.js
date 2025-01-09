require("@nomicfoundation/hardhat-toolbox");
require('@openzeppelin/hardhat-upgrades');

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.25",
  paths: {
    sources: "./V1",  // Set the path to the contracts folder
    tests: "./V1",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};
