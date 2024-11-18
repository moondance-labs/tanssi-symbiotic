// OperatorRegistryAPI.test.ts
import { ethers } from "ethers";
import { OperatorRegistryAPI } from "../../registry/operator_registry/operator_registry";
import { OPERATOR_PRIVATE_KEY } from "../../config";

describe("OperatorRegistryAPI", () => {
  let operatorRegistry: OperatorRegistryAPI;
  const OPERATOR_REGISTRY_ADDRESS =
    "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707";
  const DEFAULT_OPERATOR_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const operatorWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, provider);

    operatorRegistry = new OperatorRegistryAPI(
      OPERATOR_REGISTRY_ADDRESS,
      operatorWallet
    );
  });

  test("registerOperator", async () => {
    await expect(operatorRegistry.registerOperator()).resolves.not.toThrow();
  });

  test("should fail to double registerOperator", async () => {
    try {
      await operatorRegistry.registerOperator();
    } catch (error) {
      expect(error.message.includes("0x42ee68b5")).toBe(true);
    }
  });
  test("totalEntities", async () => {
    const totalEntities = await operatorRegistry.totalEntities();
    expect(totalEntities.toNumber()).toBe(1);
  });

  test("entity", async () => {
    const entity = await operatorRegistry.entity(0);
    expect(entity).toBe(DEFAULT_OPERATOR_ADDRESS);
  });

  test("isEntity", async () => {
    const isEntity = await operatorRegistry.isEntity(DEFAULT_OPERATOR_ADDRESS);
    expect(isEntity).toBe(true);
  });
});
