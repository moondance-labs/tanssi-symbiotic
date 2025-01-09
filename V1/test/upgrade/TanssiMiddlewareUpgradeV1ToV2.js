const { expect } = require("chai");
const { ethers, upgrades } = require("hardhat");

describe("TanssiMiddlewareV1 to TanssiMiddlewareV2Mock Upgrade", function () {
  let tanssiMiddlewareV1, tanssiMiddlewareV2;
  let owner, otherAccount;

  beforeEach(async function () {
    [owner, otherAccount] = await ethers.getSigners();

    // Deploy TanssiMiddlewareV1 as an upgradeable proxy
    const TanssiMiddlewareV1Factory = await ethers.getContractFactory("TanssiMiddlewareV1");
    tanssiMiddlewareV1 = await upgrades.deployProxy(
      TanssiMiddlewareV1Factory,
      [1, owner.address, "0x"],
      { initializer: "initialize(uint64,address,bytes)" }
    );

    await tanssiMiddlewareV1.waitForDeployment();
    console.log("tanssiMiddlewareV1 deployed to:", await tanssiMiddlewareV1.getAddress());
  });

  it("should upgrade to V2 and enable new functionality", async function () {
    // Deploy TanssiMiddlewareV2Mock
    const TanssiMiddlewareV2MockFactory = await ethers.getContractFactory("TanssiMiddlewareV2Mock");
    const initialValue = ethers.parseUnits("33", "ether");
    const initData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [initialValue]);

    // Upgrade the proxy to use V2
    tanssiMiddlewareV2 = await upgrades.upgradeProxy(await tanssiMiddlewareV1.getAddress(), TanssiMiddlewareV2MockFactory, {
        call: {
          fn: "initialize",
          args: [2, owner.address, initData],
        },
      });

    await tanssiMiddlewareV2.waitForDeployment();

    // Check the version is still accessible
    expect(await tanssiMiddlewareV2.version()).to.equal(2);
    expect(await tanssiMiddlewareV2.getNewValue()).to.equal(initialValue);

    // Call the new method added in V2
    const result = await tanssiMiddlewareV2.newFeature();
    expect(result).to.equal("New Feature Activated");
  });

  it("should prevent non-owners from upgrading", async function () {
    // Deploy TanssiMiddlewareV2Mock
    const TanssiMiddlewareV2MockFactory = await ethers.getContractFactory("TanssiMiddlewareV2Mock");

    // Attempt upgrade by non-owner
    await expect(
        upgrades.upgradeProxy(await tanssiMiddlewareV1.getAddress(), TanssiMiddlewareV2MockFactory.connect(otherAccount), {
            call: {
              fn: "initialize",
              args: [2, owner.address, "0x"],
            },
          })
    ).to.be.reverted;
  });
});
