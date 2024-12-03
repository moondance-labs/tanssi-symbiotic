import { ethers } from "ethers";
import { FACTORY_ABI } from "./migratable_factory_abi";
import { validateAddress } from "../../utils";
import { OPERATOR_ADDRESS } from "../../config";

/**
 * @notice API for interacting with a all type of Factory (VaultFactory, DelegatorFactory, SlasherFactory)
 */
export class MigratableFactoryAPI {
  private contract: ethers.Contract;

  constructor(factoryAddress: string, wallet: ethers.Wallet) {
    validateAddress(factoryAddress);
    this.contract = new ethers.Contract(factoryAddress, FACTORY_ABI, wallet);
  }

  /**
   * @notice Get the last available version.
   * @return version of the last implementation
   * @dev If zero, no implementations are whitelisted.
   */
  async lastVersion(): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.lastVersion();
      return result;
    } catch (error) {
      throw new Error(`Failed to get last version: ${error.message}`);
    }
  }

  /**
   * @notice Get the implementation for a given version.
   * @param version version to get the implementation for
   * @return address of the implementation
   * @dev Reverts when an invalid version.
   */
  async implementation(version: number): Promise<string> {
    try {
      const result = await this.contract.implementation(version);

      if (!ethers.utils.isAddress(result)) {
        throw new Error(`Invalid address returned: ${result}`);
      }

      const checksumAddress = ethers.utils.getAddress(result);
      return checksumAddress;
    } catch (error) {
      throw new Error(
        `Failed to get implementation for type ${version}: ${error.message}`
      );
    }
  }

  /**
   * @notice Whitelist a new implementation for entities.
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
   * @notice Blacklist a version of entities.
   * @param version version to blacklist
   * @dev The given version will still be deployable.
   */
  async blacklist(version: number): Promise<void> {
    try {
      await this.contract.blacklist(version);
    } catch (error) {
      throw new Error(`Failed to blacklist type: ${error.message}`);
    }
  }

  /**
   * @notice Get if a version is blacklisted (e.g., in case of invalid implementation).
   * @param version version to check
   * @return whether the version is blacklisted
   * @dev The given version is still deployable.
   */
  async blacklisted(version: number): Promise<boolean> {
    try {
      const result = await this.contract.blacklisted(version);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to check if type ${version} is blacklisted: ${error.message}`
      );
    }
  }

  /**
   * @notice Create a new entity at the factory.
   * @param version version of the entity
   * @param owner owner of the entity
   * @param data initial data for the entity creation
   * @return address of the entity
   * @dev CREATE2 salt is constructed from the given parameters.
   */
  async create(version: number, owner: string, data: string): Promise<string> {
    try {
      const tx = await this.contract.create(version, owner, data);
      const receipt = await tx.wait();

      const lastEvent = receipt.events?.[receipt.events.length - 1];

      if (!lastEvent || lastEvent.event !== "AddEntity") {
        throw new Error("AddEntity event not found in transaction receipt");
      }

      return lastEvent.args[0];
    } catch (error) {
      throw new Error(`Failed to create entity: ${error.message}`);
    }
  }

  /**
   * @notice Migrate a given entity to a given newer version.
   * @param entity address of the entity to migrate
   * @param newVersion new version to migrate to
   * @param data some data to reinitialize the contract with
   * @dev Only the entity's owner can call this function.
   */
  async migrate(
    entity: string,
    newVersion: number,
    data: string
  ): Promise<void> {
    try {
      await this.contract.migrate(entity, newVersion, data);
    } catch (error) {
      throw new Error(`Failed to migrate entity: ${error.message}`);
    }
  }
}
