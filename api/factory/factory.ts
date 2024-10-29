import { ethers } from "ethers";
import { FACTORY_ABI } from "./factory_abi";
import { validateAddress } from "../utils";

/**
 * @notice API for interacting with a all type of Factory (VaultFactory, DelegatorFactory, SlasherFactory)
 */
export class FactoryAPI {
  private contract: ethers.Contract;

  constructor(factoryAddress: string, wallet: ethers.Wallet) {
    validateAddress(factoryAddress);
    this.contract = new ethers.Contract(factoryAddress, FACTORY_ABI, wallet);
  }

  /**
   * @notice Get the total number of whitelisted types.
   * @return total number of types
   */
  async totalTypes(): Promise<number> {
    try {
      const result = await this.contract.totalTypes();
      return result;
    } catch (error) {
      throw new Error(`Failed to get total types: ${error.message}`);
    }
  }

  /**
   * @notice Get the implementation for a given type.
   * @param type_ position to get the implementation at
   * @return address of the implementation
   */
  async implementation(type_: number): Promise<string> {
    try {
      const result = await this.contract.implementation(type_);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get implementation for type ${type_}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get if a type is blacklisted (e.g., in case of invalid implementation).
   * @param type_ type to check
   * @return whether the type is blacklisted
   * @dev The given type is still deployable.
   */
  async blacklisted(type_: number): Promise<boolean> {
    try {
      const result = await this.contract.blacklisted(type_);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to check if type ${type_} is blacklisted: ${error.message}`
      );
    }
  }

  /**
   * @notice Whitelist a new type of entity.
   * @param implementation address of the new implementation
   */
  async whitelist(implementation: string): Promise<void> {
    validateAddress(implementation);
    try {
      await this.contract.whitelist(implementation);
    } catch (error) {
      throw new Error(`Failed to whitelist implementation: ${error.message}`);
    }
  }

  /**
   * @notice Blacklist a type of entity.
   * @param type_ type to blacklist
   * @dev The given type will still be deployable.
   */
  async blacklist(type_: number): Promise<void> {
    try {
      await this.contract.blacklist(type_);
    } catch (error) {
      throw new Error(`Failed to blacklist type: ${error.message}`);
    }
  }
  /**
   * @notice Create a new entity at the factory.
   * @param type_ type's implementation to use
   * @param data initial data for the entity creation
   * @return address of the entity
   * @dev CREATE2 salt is constructed from the given parameters.
   */
  async create(type_: number, data: string): Promise<string> {
    try {
      const tx = await this.contract.create(type_, data);
      const receipt = await tx.wait();

      const { entity_ } = this.contract.interface.decodeFunctionResult(
        "create",
        receipt.logs[receipt.logs.length - 1].data
      );
      return entity_;
    } catch (error) {
      throw new Error(`Failed to create entity: ${error.message}`);
    }
  }
}
