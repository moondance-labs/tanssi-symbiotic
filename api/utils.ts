import { ethers } from "ethers";

/**
 * Utility method to validate Ethereum address
 * @param address Address to validate
 * @throws SlasherError if address is invalid
 */

export function validateAddress(address: string): void {
  if (!ethers.utils.isAddress(address)) {
    throw new Error(`Invalid Ethereum address: ${address}`);
  }
}
