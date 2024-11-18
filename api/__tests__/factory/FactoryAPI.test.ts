import { ethers } from "ethers";
import {
  COLLATERAL_ADDRESS,
  DELEGATOR_FACTORY_ADDRESS,
  ONE_DAY,
  OWNER_ADDRESS,
  OWNER_PRIVATE_KEY,
  SLASHER_FACTORY_ADDRESS,
  VAULT_FACTORY_ADDRESS,
} from "../../config";

import { FactoryAPI } from "../../factory/factory/factory";
import {
  DelegatorParams,
  DelegatorType,
  SlasherParams,
  VaultParams,
} from "../../types";
import {
  encodeDelegatorFactoryParams,
  encodeDelegatorParams,
  encodeSlasherFactoryParams,
  encodeSlasherParams,
  encodeVaultParams,
} from "../../utils";
import { MigratableFactoryAPI } from "../../factory/migratables_factory/migratable_factory";

describe("FactoryAPI", () => {
  let slasherFactoryAPI: FactoryAPI;
  let delegatorFactoryAPI: FactoryAPI;
  let vaultFactoryAPI: MigratableFactoryAPI;

  let newlyCreatedVaultAddress: string;

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);

    slasherFactoryAPI = new FactoryAPI(SLASHER_FACTORY_ADDRESS, ownerWallet);
    delegatorFactoryAPI = new FactoryAPI(
      DELEGATOR_FACTORY_ADDRESS,
      ownerWallet
    );

    vaultFactoryAPI = new MigratableFactoryAPI(
      VAULT_FACTORY_ADDRESS,
      ownerWallet
    );
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
    newlyCreatedVaultAddress = result;
  });

  describe("SlasherFactory", () => {
    test("should return total number of types", async () => {
      const total = await slasherFactoryAPI.totalTypes();
      expect(total.toNumber()).toBe(2);
    });

    test("should return implementation address for valid type", async () => {
      const implementation = await slasherFactoryAPI.implementation(1);
      expect(ethers.utils.isAddress(implementation)).toBe(true);
    });

    test("should return blacklist status for valid type", async () => {
      const isBlacklisted = await slasherFactoryAPI.blacklisted(1);
      expect(typeof isBlacklisted).toBe("boolean");
    });

    test("should blacklist existing type", async () => {
      await expect(slasherFactoryAPI.blacklist(0)).resolves.not.toThrow();
    });

    describe("create", () => {
      test("should create vault with correct parameters", async () => {
        const slasherParams: SlasherParams = {
          slasherIndex: 0,
          vetoDuration: ONE_DAY * 7,
        };
        const encodedParams = encodeSlasherFactoryParams(
          newlyCreatedVaultAddress,
          slasherParams
        );
        const result = await slasherFactoryAPI.create(0, encodedParams);
        expect(ethers.utils.isAddress(result)).toBe(true);
      });

      test("should throw error for invalid type", async () => {
        const mockData = ethers.utils.defaultAbiCoder.encode(["uint256"], [1]);
        await expect(slasherFactoryAPI.create(999, mockData)).rejects.toThrow();
      });
    });
  });

  describe("DelegatorFactory", () => {
    test("should return total number of types", async () => {
      const total = await delegatorFactoryAPI.totalTypes();
      expect(total.toNumber()).toBe(3);
    });

    test("should return implementation address for valid type", async () => {
      const implementation = await delegatorFactoryAPI.implementation(1);
      expect(ethers.utils.isAddress(implementation)).toBe(true);
    });

    test("should return blacklist status for valid type", async () => {
      const isBlacklisted = await slasherFactoryAPI.blacklisted(1);
      expect(typeof isBlacklisted).toBe("boolean");
    });

    test("should blacklist existing type", async () => {
      await expect(delegatorFactoryAPI.blacklist(1)).resolves.not.toThrow();
    });

    describe("create", () => {
      test("should create delegator with correct parameters", async () => {
        const delegatorParams: DelegatorParams = {
          owner: OWNER_ADDRESS,
          networkLimitSetRoleHolders: [OWNER_ADDRESS],
          operatorNetworkSharesSetRoleHolders: [OWNER_ADDRESS],
        };

        const encodedParams = encodeDelegatorFactoryParams(
          newlyCreatedVaultAddress,
          delegatorParams
        );

        const result = await delegatorFactoryAPI.create(
          DelegatorType.NETWORK_RESTAKE,
          encodedParams
        );
        expect(ethers.utils.isAddress(result)).toBe(true);
      });

      test("should throw error for invalid type", async () => {
        const mockData = ethers.utils.defaultAbiCoder.encode(["uint256"], [1]);
        await expect(
          delegatorFactoryAPI.create(999, mockData)
        ).rejects.toThrow();
      });

      test("should throw error for invalid data", async () => {
        await expect(
          delegatorFactoryAPI.create(0, "invalid_data")
        ).rejects.toThrow();
      });
    });
  });
});
