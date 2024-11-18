import { ethers } from "ethers";
import { NetworkRegistryAPI } from "../../registry/network_registry/network_registry";
import {
  NETWORK_ADDRESS,
  NETWORK_PRIVATE_KEY,
  NETWORK_REGISTRY_ADDRESS,
} from "../../config";

describe("NetworkRegistryAPI", () => {
  let networkRegistry: NetworkRegistryAPI;

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const wallet = new ethers.Wallet(NETWORK_PRIVATE_KEY, provider);
    networkRegistry = new NetworkRegistryAPI(NETWORK_REGISTRY_ADDRESS, wallet);
  });

  test("registerNetwork", async () => {
    await expect(networkRegistry.registerNetwork()).resolves.not.toThrow();
  });

  test("should fail to double registerNetwork", async () => {
    try {
      await networkRegistry.registerNetwork();
    } catch (error) {
      expect(error.message.includes("0xad5fcda5")).toBe(true);
    }
  });
  test("totalEntities", async () => {
    const totalEntities = await networkRegistry.totalEntities();
    expect(totalEntities.toNumber()).toBe(2);
  });

  test("entity", async () => {
    const entity = await networkRegistry.entity(1);
    expect(entity).toBe(NETWORK_ADDRESS);
  });

  test("isEntity", async () => {
    const isEntity = await networkRegistry.isEntity(NETWORK_ADDRESS);
    expect(isEntity).toBe(true);
  });
});
