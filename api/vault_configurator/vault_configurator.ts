import { ethers } from "ethers";
import { validateAddress } from "../utils";
import { VAULT_CONFIGURATOR_ABI } from "./vault_configurator_abi";
import { VaultConfiguratorParams } from "../types";

/**
 * @notice API for interacting with a Vault contract
 */
export class VaultConfiguratorAPI {
  private contract: ethers.Contract;

  constructor(vaultConfiguratorAddress: string, wallet: ethers.Wallet) {
    validateAddress(vaultConfiguratorAddress);
    this.contract = new ethers.Contract(
      vaultConfiguratorAddress,
      VAULT_CONFIGURATOR_ABI,
      wallet
    );
  }

  /**
   * @notice Get the vault factory's address.
   * @return address of the vault factory
   */
  async VAULT_FACTORY(): Promise<string> {
    try {
      const result = await this.contract.VAULT_FACTORY();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get VAULT_FACTORY: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get the delegator factory's address.
   * @return address of the delegator factory
   */
  async DELEGATOR_FACTORY(): Promise<string> {
    try {
      const result = await this.contract.DELEGATOR_FACTORY();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get DELEGATOR_FACTORY: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get the slasher factory's address.
   * @return address of the slasher factory
   */
  async SLASHER_FACTORY(): Promise<string> {
    try {
      const result = await this.contract.SLASHER_FACTORY();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get SLASHER_FACTORY: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Create a new vault with a delegator and a slasher.
   * @param params initial parameters needed for a vault with a delegator and a slasher deployment
   * @return vault address of the vault
   * @return delegator address of the delegator
   * @return slasher address of the slasher
   */
  async create(
    params: VaultConfiguratorParams
  ): Promise<{ vault: string; delegator: string; slasher: string }> {
    try {
      const result = await this.contract.callStatic.create(params);
      const { vault, delegator, slasher } = result;
      const tx = await this.contract.create(params);

      await tx.wait();

      return { vault, delegator, slasher };
    } catch (error) {
      throw new Error(`Failed to create vault: ${error.message}`, error.code);
    }
  }
}
