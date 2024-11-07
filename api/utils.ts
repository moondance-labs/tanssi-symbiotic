import { ethers } from "ethers";
import { DelegatorParams, SlasherParams, VaultParams } from "./types";
import { ZERO_ADDRESS } from "./config";

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

/**
 * Encodes the vault parameters into bytes
 * @param params that needs to be encoded
 * @returns bytes abi encoded params
 */
export function encodeVaultParams(params: VaultParams): string {
  const types = [
    "address", // collateral
    "address", // burner
    "uint48", // epochDuration
    "bool", // depositWhitelist
    "bool", // isDepositLimit
    "uint256", // depositLimit
    "address", // defaultAdminRoleHolder
    "address", // depositWhitelistSetRoleHolder
    "address", // depositorWhitelistRoleHolder
    "address", // isDepositLimitSetRoleHolder
    "address", // depositLimitSetRoleHolder
  ];

  const values = [
    params.collateral,
    "0x000000000000000000000000000000000000dEaD",
    params.epochDuration,
    params.depositWhitelist,
    params.depositLimit !== 0,
    params.depositLimit,
    params.owner,
    params.owner,
    params.owner,
    params.owner,
    params.owner,
  ];

  return ethers.utils.defaultAbiCoder.encode(types, values);
}

export function encodeDelegatorParams(params: DelegatorParams): string {
  const types = ["tuple(tuple(address,address,address), address[], address[])"];

  const values = [
    [
      [params.owner, ZERO_ADDRESS, params.owner],
      params.networkLimitSetRoleHolders,
      params.operatorNetworkSharesSetRoleHolders,
    ],
  ];
  return ethers.utils.defaultAbiCoder.encode(types, values);
}

export function encodeSlasherParams(params: SlasherParams): string {
  if (params.slasherIndex === 0) {
    return ethers.utils.defaultAbiCoder.encode(["tuple(bool)"], [[false]]);
  }

  return ethers.utils.defaultAbiCoder.encode(
    ["tuple(bool)", "uint48", "uint256"],
    [[false], params.vetoDuration, 3]
  );
}

export function encodeDelegatorFactoryParams(
  vault: string,
  params: DelegatorParams
): string {
  return ethers.utils.defaultAbiCoder.encode(
    ["address", "bytes"],
    [vault, encodeDelegatorParams(params)]
  );
}

export function encodeSlasherFactoryParams(
  vault: string,
  params: SlasherParams
): string {
  return ethers.utils.defaultAbiCoder.encode(
    ["address", "bytes"],
    [vault, encodeSlasherParams(params)]
  );
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
