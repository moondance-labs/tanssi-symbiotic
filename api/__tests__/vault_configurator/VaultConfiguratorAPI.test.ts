import { ethers } from "ethers";
import {
  COLLATERAL_ADDRESS,
  DELEGATOR_FACTORY_ADDRESS,
  ONE_DAY,
  OWNER_ADDRESS,
  OWNER_PRIVATE_KEY,
  SLASHER_FACTORY_ADDRESS,
  VAULT_CONFIGURATOR_ADDRESS,
  VAULT_FACTORY_ADDRESS,
} from "../../config";

import { VaultConfiguratorAPI } from "../../vault_configurator/vault_configurator";
import {
  DelegatorParams,
  SlasherParams,
  VaultConfiguratorParams,
  VaultParams,
} from "../../types";
import {
  encodeDelegatorParams,
  encodeSlasherParams,
  encodeVaultParams,
} from "../../utils";

describe("VaultAPI", () => {
  let vaultConfigurator: VaultConfiguratorAPI;

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );
    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
    vaultConfigurator = new VaultConfiguratorAPI(
      VAULT_CONFIGURATOR_ADDRESS,
      ownerWallet
    );
  });

  test("VAULT_FACTORY", async () => {
    await expect(vaultConfigurator.VAULT_FACTORY()).resolves.toBe(
      VAULT_FACTORY_ADDRESS
    );
  });

  test("NETWORK_MIDDLEWARE_SERVICE", async () => {
    await expect(vaultConfigurator.DELEGATOR_FACTORY()).resolves.toBe(
      DELEGATOR_FACTORY_ADDRESS
    );
  });

  test("NETWORK_REGISTRY", async () => {
    await expect(vaultConfigurator.SLASHER_FACTORY()).resolves.toBe(
      SLASHER_FACTORY_ADDRESS
    );
  });

  describe("create", () => {
    test("should create vault, delegator and slasher with correct parameters", async () => {
      const vaultParams: VaultParams = {
        collateral: COLLATERAL_ADDRESS,
        epochDuration: ONE_DAY * 12,
        depositWhitelist: false,
        depositLimit: 0,
        owner: OWNER_ADDRESS,
      };
      const encodedVaultParamsParams = encodeVaultParams(vaultParams);

      const slasherParams: SlasherParams = {
        slasherIndex: 0,
        vetoDuration: ONE_DAY * 7,
      };
      const encodedSlasherParams = encodeSlasherParams(slasherParams);
      const delegatorParams: DelegatorParams = {
        owner: OWNER_ADDRESS,
        networkLimitSetRoleHolders: [OWNER_ADDRESS],
        operatorNetworkSharesSetRoleHolders: [OWNER_ADDRESS],
      };

      const encodedDelegatorParams = encodeDelegatorParams(delegatorParams);
      const vaultConfiguratorParams: VaultConfiguratorParams = {
        version: 1,
        owner: OWNER_ADDRESS,
        vaultParams: encodedVaultParamsParams,
        delegatorIndex: 0,
        delegatorParams: encodedDelegatorParams,
        withSlasher: true,
        slasherIndex: 0,
        slasherParams: encodedSlasherParams,
      };

      const { vault, delegator, slasher } = await vaultConfigurator.create(
        vaultConfiguratorParams
      );
      expect(ethers.utils.isAddress(vault)).toBe(true);
      expect(ethers.utils.isAddress(delegator)).toBe(true);
      expect(ethers.utils.isAddress(slasher)).toBe(true);
    });
  });
});
