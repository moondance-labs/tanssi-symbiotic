import { ethers } from "ethers";
import { subnetwork } from "../../utils";
import {
  NETWORK_ADDRESS,
  NETWORK_MIDDLEWARE_SERVICE_ADDRESS,
  NETWORK_REGISTRY_ADDRESS,
  OPERATOR_ADDRESS,
  OWNER_PRIVATE_KEY,
  RESOLVER_ADDRESS,
  SLASHER_VETOED_ADDRESS,
  VAULT_FACTORY_ADDRESS,
  VAULT_SLASHABLE_ADDRESS,
  VAULT_VETOED_ADDRESS,
  ZERO_ADDRESS,
} from "../../config";
import { VetoSlasherAPI } from "../../slasher/veto_slasher/veto_slasher";

describe("VetoSlasherAPI", () => {
  let vetoSlasher: VetoSlasherAPI;
  const subNetwork = subnetwork(NETWORK_ADDRESS, 0);

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );
    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
    vetoSlasher = new VetoSlasherAPI(SLASHER_VETOED_ADDRESS, ownerWallet);
  });

  test("VAULT_FACTORY", async () => {
    await expect(vetoSlasher.VAULT_FACTORY()).resolves.toBe(
      VAULT_FACTORY_ADDRESS
    );
  });

  test("NETWORK_MIDDLEWARE_SERVICE", async () => {
    await expect(vetoSlasher.NETWORK_MIDDLEWARE_SERVICE()).resolves.toBe(
      NETWORK_MIDDLEWARE_SERVICE_ADDRESS
    );
  });

  test("NETWORK_REGISTRY", async () => {
    const netwokRegistry = await vetoSlasher.NETWORK_REGISTRY();
    await expect(vetoSlasher.NETWORK_REGISTRY()).resolves.toBe(
      NETWORK_REGISTRY_ADDRESS
    );
  });

  test("vault", async () => {
    await expect(vetoSlasher.vault()).resolves.toBe(VAULT_VETOED_ADDRESS);
  });

  test("isBurnerHook", async () => {
    await expect(vetoSlasher.isBurnerHook()).resolves.toBe(false);
  });

  test("latestSlashedCaptureTimestamp", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
    };
    await expect(
      vetoSlasher.latestSlashedCaptureTimestamp(params)
    ).resolves.toBeGreaterThanOrEqual(0);
  });

  test("vetoDuration", async () => {
    await expect(vetoSlasher.vetoDuration()).resolves.toBeGreaterThan(0);
  });

  test("resolverSetEpochsDelay", async () => {
    await expect(vetoSlasher.resolverSetEpochsDelay()).resolves.toBeGreaterThan(
      0
    );
  });

  test("slashRequestsLength", async () => {
    await expect(
      vetoSlasher.slashRequestsLength()
    ).resolves.toBeGreaterThanOrEqual(0);
  });

  test("resolverAt", async () => {
    const resolverAt = await vetoSlasher.resolverAt(
      subNetwork,
      Date.now(),
      "0x"
    );
    expect(resolverAt).toBe(ZERO_ADDRESS);
  });

  test("resolver", async () => {
    const resolver = await vetoSlasher.resolver(subNetwork, "0x");
    expect(resolver).toBe(ZERO_ADDRESS);
  });

  test("cumulativeSlashAt", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
      captureTimestamp: Date.now(),
      hints: "0x",
    };
    const cumulativeSlashAt = await vetoSlasher.cumulativeSlashAt(params);
    expect(cumulativeSlashAt.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("cumulativeSlash", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
    };
    const cumulativeSlash = await vetoSlasher.cumulativeSlash(params);
    expect(cumulativeSlash.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("slashableStake", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
      captureTimestamp: Date.now(),
      hints: "0x",
    };
    const slashableStake = await vetoSlasher.slashableStake(params);
    expect(slashableStake.toNumber()).toBeGreaterThanOrEqual(0);
  });

  // Can be run only by middleware
  // test("requestSlash", async () => {
  //   const params = {
  //     subnetwork: subNetwork,
  //     operator: OPERATOR_ADDRESS,
  //     amount: ethers.BigNumber.from("1000"),
  //     captureTimestamp: Date.now(),
  //     hints: "0x",
  //   };

  //   await expect(
  //     vetoSlasher.requestSlash(params)
  //   ).resolves.toBeGreaterThanOrEqual(0);
  // });

  // test("slashRequests", async () => {
  //   const slashIndex = 0;
  //   const result = await vetoSlasher.slashRequests(slashIndex);
  // });

  // test("executeSlash", async () => {
  //   const slashedAmount = await vetoSlasher.executeSlash({
  //     slashIndex: 0,
  //     hints: "0x",
  //   });

  //   expect(slashedAmount).toBeInstanceOf(ethers.BigNumber);
  // });

  // test("vetoSlash", async () => {
  //   const params = {
  //     slashIndex: 0,
  //     hints: "0x",
  //   };

  //   await expect(vetoSlasher.vetoSlash(params)).resolves.not.toThrow();
  // });

  test("setResolver", async () => {
    const identifier = 0;
    const resolverAddress = RESOLVER_ADDRESS;
    const hints = "0x";

    await expect(
      vetoSlasher.setResolver(identifier, resolverAddress, hints)
    ).resolves.not.toThrow();
  });
});
