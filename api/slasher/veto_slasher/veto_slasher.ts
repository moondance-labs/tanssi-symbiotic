import { ethers } from "ethers";
import { VETO_SLASHER_ABI } from "./veto_slasher_abi";
import { BaseSlasherAPI, SlashParams } from "../base_slasher/base_slasher";
import { validateAddress } from "../../utils";

type ExecuteSlashParams = {
  slashIndex: number;
  hints: string;
};

type VetoSlashParams = {
  slashIndex: number;
  hints: string;
};

export class VetoSlasherAPI extends BaseSlasherAPI {
  constructor(slasherAddress: string, wallet: ethers.Wallet) {
    super(slasherAddress, wallet);
    this.contract = new ethers.Contract(
      slasherAddress,
      VETO_SLASHER_ABI,
      wallet
    );
  }

  /**
   * @notice Get the network registry's address.
   * @return address of the network registry
   */
  async NETWORK_REGISTRY(): Promise<string> {
    try {
      const result = await this.contract.NETWORK_REGISTRY();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get NETWORK_REGISTRY: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get a particular slash request.
   * @param slashIndex index of the slash request
   * @return subnetwork subnetwork that requested the slash
   * @return operator operator that could be slashed (if the request is not vetoed)
   * @return amount maximum amount of the collateral to be slashed
   * @return captureTimestamp time point when the stake was captured
   * @return vetoDeadline deadline for the resolver to veto the slash (exclusively)
   * @return completed if the slash was vetoed/executed
   */
  async slashRequests(index: number): Promise<string> {
    try {
      const result = await this.contract.slashRequests(index);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get slash request at index ${index}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a duration during which resolvers can veto slash requests.
   * @return duration of the veto period
   */
  async vetoDuration(): Promise<number> {
    try {
      const result = await this.contract.vetoDuration();
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get veto duration: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get a delay for networks in epochs to update a resolver.
   * @return updating resolver delay in epochs
   */
  async resolverSetEpochsDelay(): Promise<number> {
    try {
      const result = await this.contract.resolverSetEpochsDelay();
      return result.toNumber();
    } catch (error) {
      throw new Error(
        `Failed to get resolver set epochs delay: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * Get the total number of slash requests
   * @returns Promise resolving to the number of slash requests
   */
  async slashRequestsLength(): Promise<number> {
    try {
      const result = await this.contract.slashRequestsLength();
      return result.toNumber();
    } catch (error) {
      throw new Error(
        `Failed to get slash requests length: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * Get resolver at specific timestamp
   * @param subnetwork The subnetwork identifier
   * @param timestamp The timestamp to query
   * @param hint Lookup hint
   * @returns Promise resolving to resolver address
   */
  async resolverAt(
    subnetwork: string,
    timestamp: number,
    hint: string
  ): Promise<string> {
    try {
      const result = await this.contract.resolverAt(
        subnetwork,
        timestamp,
        hint
      );
      return result;
    } catch (error) {
      throw Error(
        `Failed to get resolver at timestamp: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * Get current resolver
   * @param subnetwork The subnetwork identifier
   * @param hint Lookup hint
   * @returns Promise resolving to current resolver address
   */
  async resolver(subnetwork: string, hint: string): Promise<string> {
    try {
      const result = await this.contract.resolver(subnetwork, hint);
      return result;
    } catch (error) {
      throw Error(
        `Failed to get current resolver: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * Request a slash operation
   * @param subnetwork The subnetwork identifier
   * @param operator The operator address
   * @param amount The amount to slash
   * @param captureTimestamp The timestamp to capture
   * @param hints Additional hints
   * @returns Promise resolving to the slash index
   */
  async requestSlash({
    subnetwork,
    operator,
    amount,
    captureTimestamp,
    hints,
  }: Required<SlashParams>): Promise<number> {
    try {
      const tx = await this.contract.requestSlash(
        subnetwork,
        operator,
        amount,
        captureTimestamp,
        hints
      );

      const receipt = await tx.wait();

      const { slashIndex } = this.contract.interface.decodeFunctionResult(
        "requestSlash",
        receipt.logs[receipt.logs.length - 1].data
      );
      return slashIndex;
    } catch (error) {
      throw Error(`Failed to request slash: ${error.message}`, error.code);
    }
  }

  /**
   * Execute a pending slash request
   * @param slashIndex The index of the slash request
   * @param hints Additional hints
   * @returns Promise resolving to the slashed amount
   */
  async executeSlash({
    slashIndex,
    hints,
  }: ExecuteSlashParams): Promise<ethers.BigNumber> {
    try {
      const tx = await this.contract.executeSlash(slashIndex, hints);

      const receipt = await tx.wait();

      const { slashedAmount } = this.contract.interface.decodeFunctionResult(
        "executeSlash",
        receipt.logs[receipt.logs.length - 1].data
      );
      return slashedAmount;
    } catch (error) {
      throw new Error(`Failed to execute slash: ${error.message}`, error.code);
    }
  }

  /**
   * Veto a pending slash request
   * @param slashIndex The index of the slash request
   * @param hints Additional hints
   */
  async vetoSlash({ slashIndex, hints }: VetoSlashParams): Promise<void> {
    try {
      const tx = await this.contract.vetoSlash(slashIndex, hints);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to veto slash: ${error.message}`, error.code);
    }
  }

  /**
   * Set resolver for a subnetwork to veto slash requests
   * @param identifier The identifier number
   * @param resolver The resolver address
   * @param hints Additional hints
   */
  async setResolver(identifier: number, resolver: string, hints: string) {
    try {
      validateAddress(resolver);
      const tx = await this.contract.setResolver(identifier, resolver, hints);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to set resolver: ${error.message}`, error.code);
    }
  }
}
