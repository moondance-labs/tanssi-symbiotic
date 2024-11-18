import { ethers } from "ethers";
import { OPERATOR_REGISTRY_ABI } from "./operator_registry_abi";
import { RegistryAPI } from "../registry";

/**
 * @notice API for interacting with the Operator Registry contract
 */
export class OperatorRegistryAPI extends RegistryAPI {
  constructor(operatorRegistryAddress: string, wallet: ethers.Wallet) {
    super(operatorRegistryAddress, wallet);
    this.contract = new ethers.Contract(
      operatorRegistryAddress,
      OPERATOR_REGISTRY_ABI,
      wallet
    );
  }

  /**
   * @notice Register the caller as an operator.
   */
  async registerOperator(): Promise<void> {
    try {
      const tx = await this.contract.registerOperator();
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to register operator: ${error.message}`);
    }
  }
}
