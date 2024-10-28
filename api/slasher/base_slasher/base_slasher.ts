import { ethers } from "ethers";
import { BASE_SLASHER_ABI } from "./base_slasher_abi";

export type SlashParams = {
  subnetwork: string;
  operator: string;
  amount?: ethers.BigNumber;
  captureTimestamp?: number;
  hints?: string;
};

export abstract class BaseSlasherAPI {
  protected contract: ethers.Contract;

  constructor(slasherAddress: string, wallet: ethers.Wallet) {
    if (!ethers.utils.isAddress(slasherAddress)) {
      throw new Error("Invalid slasher contract address");
    }
    this.contract = new ethers.Contract(
      slasherAddress,
      BASE_SLASHER_ABI,
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
   * @notice Get the network middleware service's address.
   * @return address of the network middleware service
   */
  async NETWORK_MIDDLEWARE_SERVICE(): Promise<string> {
    try {
      const result = await this.contract.NETWORK_MIDDLEWARE_SERVICE();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get NETWORK_MIDDLEWARE_SERVICE: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get the vault's address.
   * @return address of the vault to perform slashings on
   */
  async vault(): Promise<string> {
    try {
      const result = await this.contract.vault();
      return result;
    } catch (error) {
      throw new Error(`Failed to get vault: ${error.message}`, error.code);
    }
  }

  /**
   * @notice Get if the burner is needed to be called on a slashing.
   * @return if the burner is a hook
   */
  async isBurnerHook(): Promise<boolean> {
    try {
      const result = await this.contract.isBurnerHook();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get isBurnerHook: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get the latest capture timestamp that was slashed on a subnetwork.
   * @param subnetwork full identifier of the subnetwork (address of the network concatenated with the uint96 identifier)
   * @param operator address of the operator
   * @return latest capture timestamp that was slashed
   */
  async latestSlashedCaptureTimestamp({
    subnetwork,
    operator,
  }: SlashParams): Promise<number> {
    try {
      const result = await this.contract.latestSlashedCaptureTimestamp(
        subnetwork,
        operator
      );
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get latest slashed capture timestamp: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get cumulative slash at specific timestamp
   * @param subnetwork Subnetwork address
   * @param operator Operator address
   * @param captureTimestamp Capture timestamp
   * @param hints hint for the checkpoint index, an abi encoded bytes array
   * @returns Promise resolving to cumulative slash amount
   */
  async cumulativeSlashAt({
    subnetwork,
    operator,
    captureTimestamp,
    hints,
  }: SlashParams): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.cumulativeSlashAt(
        subnetwork,
        operator,
        captureTimestamp,
        hints
      );
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get cumulative slash at timestamp: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get latest cumulative slash
   * @param subnetwork Subnetwork address
   * @param operator Operator address
   * @returns Promise resolving to latest cumulative slash amount
   */
  async cumulativeSlash({
    subnetwork,
    operator,
  }: SlashParams): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.cumulativeSlash(subnetwork, operator);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get cumulative slash: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get slashable stake amount
   * @param subnetwork Subnetwork address
   * @param operator Operator address
   * @param captureTimestamp Capture timestamp
   * @param hints hints hints for the checkpoints' indexes, an abi encoded bytes array
   * @returns Promise resolving to slashable stake amount
   */
  async slashableStake({
    subnetwork,
    operator,
    captureTimestamp,
    hints,
  }: SlashParams): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.slashableStake(
        subnetwork,
        operator,
        captureTimestamp,
        hints
      );
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get slashable stake: ${error.message}`,
        error.code
      );
    }
  }
}
