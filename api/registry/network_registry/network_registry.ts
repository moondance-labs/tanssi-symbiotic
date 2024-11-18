import { ethers } from "ethers";
import { NETWORK_REGISTRY_ABI } from "./network_registry_abi";
import { RegistryAPI } from "../registry";

/**
 * @notice API for interacting with the Network Registry contract
 */
export class NetworkRegistryAPI extends RegistryAPI {
  constructor(networkRegistryAddress: string, wallet: ethers.Wallet) {
    super(networkRegistryAddress, wallet);
    this.contract = new ethers.Contract(
      networkRegistryAddress,
      NETWORK_REGISTRY_ABI,
      wallet
    );
  }

  /**
   * @notice Register the caller as an operator.
   */
  async registerNetwork(): Promise<void> {
    try {
      const tx = await this.contract.registerNetwork();
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to register operator: ${error.message}`);
    }
  }
}
