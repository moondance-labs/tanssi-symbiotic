import { ethers } from "ethers";
import {
  COLLATERAL_ADDRESS,
  ONE_DAY,
  OWNER_ADDRESS,
  OWNER_PRIVATE_KEY,
  VAULT_FACTORY_ADDRESS,
} from "../../config";
import { MigratableFactoryAPI } from "../../factory/migratables_factory/migratable_factory";
import { VaultParams } from "../../types";
import { encodeVaultParams } from "../../utils";

describe("FactoryAPI", () => {
  let vaultFactoryAPI: MigratableFactoryAPI;

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);

    vaultFactoryAPI = new MigratableFactoryAPI(
      VAULT_FACTORY_ADDRESS,
      ownerWallet
    );
  });

  test("should return implementation address for valid type", async () => {
    const implementation = await vaultFactoryAPI.implementation(1);
    expect(ethers.utils.isAddress(implementation)).toBe(true);
  });

  test("should return blacklist status for valid type", async () => {
    const isBlacklisted = await vaultFactoryAPI.blacklisted(1);
    expect(typeof isBlacklisted).toBe("boolean");
  });

  test("should blacklist existing type", async () => {
    await expect(vaultFactoryAPI.blacklist(1)).resolves.not.toThrow();
  });

  describe("create", () => {
    test("should create vault with correct parameters", async () => {
      const vaultParams: VaultParams = {
        collateral: COLLATERAL_ADDRESS,
        epochDuration: ONE_DAY * 12,
        depositWhitelist: false,
        depositLimit: 0,
        owner: OWNER_ADDRESS,
      };

      const encodedParams = encodeVaultParams(vaultParams);

      const result = await vaultFactoryAPI.create(
        1,
        OWNER_ADDRESS,
        encodedParams
      );
      expect(ethers.utils.isAddress(result)).toBe(true);
    });

    test("should throw error for invalid type", async () => {
      const mockData = ethers.utils.defaultAbiCoder.encode(["uint256"], [1]);
      await expect(
        vaultFactoryAPI.create(999, OWNER_ADDRESS, mockData)
      ).rejects.toThrow();
    });
  });
});
