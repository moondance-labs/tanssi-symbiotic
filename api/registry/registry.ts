import { ethers } from "ethers";
import { REGISTRY_ABI } from "./registry_abi";
import { validateAddress } from "../utils";

/**
 * @notice API for interacting with the Registry contract
 */
export abstract class RegistryAPI {
  protected contract: ethers.Contract;

  constructor(registryAddress: string, wallet: ethers.Wallet) {
    validateAddress(registryAddress);
    this.contract = new ethers.Contract(registryAddress, REGISTRY_ABI, wallet);
  }

  /**
   * @notice Get an entity given its index.
   * @param index index of the entity to get
   * @return address of the entity
   */
  async entity(index: number): Promise<string> {
    try {
      const result = await this.contract.entity(index);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get entity at index ${index}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get if a given address is an entity.
   * @param account address to check
   * @return if the given address is an entity
   */
  async isEntity(entity: string): Promise<boolean> {
    validateAddress(entity);
    try {
      const result = await this.contract.isEntity(entity);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to check if ${entity} is an entity: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a total number of entities.
   * @return total number of entities added
   */
  async totalEntities(): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.totalEntities();
      return result;
    } catch (error) {
      throw new Error(`Failed to get total entities: ${error.message}`);
    }
  }
}
