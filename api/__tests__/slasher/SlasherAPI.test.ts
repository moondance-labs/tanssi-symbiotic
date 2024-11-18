import { ethers } from "ethers";
import { SlasherAPI } from "../../slasher/slasher/slasher";
import { subnetwork } from "../../utils";
import {
  NETWORK_ADDRESS,
  NETWORK_MIDDLEWARE_SERVICE_ADDRESS,
  OPERATOR_ADDRESS,
  OWNER_PRIVATE_KEY,
  SLASHER_SLASHABLE_ADDRESS,
  VAULT_FACTORY_ADDRESS,
  VAULT_SLASHABLE_ADDRESS,
} from "../../config";

describe("SlasherAPI", () => {
  let slasher: SlasherAPI;
  const subNetwork = subnetwork(NETWORK_ADDRESS, 0);

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );
    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
    slasher = new SlasherAPI(SLASHER_SLASHABLE_ADDRESS, ownerWallet);
  });

  test("VAULT_FACTORY", async () => {
    await expect(slasher.VAULT_FACTORY()).resolves.toBe(VAULT_FACTORY_ADDRESS);
  });

  test("NETWORK_MIDDLEWARE_SERVICE", async () => {
    await expect(slasher.NETWORK_MIDDLEWARE_SERVICE()).resolves.toBe(
      NETWORK_MIDDLEWARE_SERVICE_ADDRESS
    );
  });

  test("vault", async () => {
    await expect(slasher.vault()).resolves.toBe(VAULT_SLASHABLE_ADDRESS);
  });

  test("isBurnerHook", async () => {
    await expect(slasher.isBurnerHook()).resolves.toBe(false);
  });

  test("latestSlashedCaptureTimestamp", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
    };
    await expect(
      slasher.latestSlashedCaptureTimestamp(params)
    ).resolves.toBeGreaterThanOrEqual(0);
  });

  test("cumulativeSlashAt", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
      captureTimestamp: Date.now(),
      hints: "0x",
    };
    const cumulativeSlashAt = await slasher.cumulativeSlashAt(params);
    expect(cumulativeSlashAt.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("cumulativeSlash", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
    };
    const cumulativeSlash = await slasher.cumulativeSlash(params);
    expect(cumulativeSlash.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("slashableStake", async () => {
    const params = {
      subnetwork: subNetwork,
      operator: OPERATOR_ADDRESS,
      captureTimestamp: Date.now(),
      hints: "0x",
    };
    const slashableStake = await slasher.slashableStake(params);
    expect(slashableStake.toNumber()).toBeGreaterThanOrEqual(0);
  });

  // This can be called only by middleware. Leaving here until middleware is pushed
  // test("slash", async () => {
  //   const params = {
  //     subnetwork: subNetwork,
  //     operator: OPERATOR_ADDRESS,
  //     amount: ethers.BigNumber.from(1000),
  //     captureTimestamp: Date.now(),
  //     hints: "0x"
  //   };
  //   await expect(slasher.slash(params)).resolves.toBeInstanceOf(ethers.BigNumber);
  // });
});
