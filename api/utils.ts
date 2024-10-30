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

// Reimplementation of the Subnetwork Solidity Library in TypeScript
export function subnetwork(network: string, identifier: number): string {
  return ethers.utils.hexlify(
    ethers.BigNumber.from(network).shl(96).add(identifier)
  );
}

export function network(subnetwork: string): string {
  return ethers.utils.getAddress(
    ethers.BigNumber.from(subnetwork).shr(96).toHexString()
  );
}

export function identifier(subnetwork: string): number {
  return ethers.BigNumber.from(subnetwork).toNumber();
}
