const { expect } = require("chai");
const { ethers, upgrades } = require("hardhat");

describe("TanssiMiddlewareV1 Proxy Deployment", function () {
  let TanssiMiddlewareV1, tanssiMiddlewareV1, owner, otherAccount;

  beforeEach(async function () {
    // Get accounts
    [owner, otherAccount] = await ethers.getSigners();

    // Deploy TanssiMiddlewareV1 using OpenZeppelin's upgradeable pattern
    const TanssiMiddlewareV1Factory = await ethers.getContractFactory("TanssiMiddlewareV1");
    tanssiMiddlewareV1 = await upgrades.deployProxy(
      TanssiMiddlewareV1Factory,
      [1, owner.address, "0x"], // Initializer arguments
      { initializer: "initialize(uint64,address,bytes)" }
    );

    await tanssiMiddlewareV1.waitForDeployment();
    console.log("tanssiMiddlewareV1 deployed to:", await tanssiMiddlewareV1.getAddress());
  });

  it("should have the correct owner", async function () {
    // Check the owner of the contract
    expect(await tanssiMiddlewareV1.owner()).to.equal(owner.address);
  });

  it("should return the correct version", async function () {
    // Check the version of the contract
    expect(await tanssiMiddlewareV1.version()).to.equal(1);
  });
});
