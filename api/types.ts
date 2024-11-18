export type VaultParams = {
  collateral: string;
  epochDuration: number;
  depositWhitelist: boolean;
  depositLimit: number;
  owner: string;
};

export type DelegatorParams = {
  owner: string;
  networkLimitSetRoleHolders: string[];
  operatorNetworkSharesSetRoleHolders: string[];
};

export type SlasherParams = {
  slasherIndex: number;
  vetoDuration: number;
};
export type VaultConfiguratorParams = {
  version: number;
  owner: string;
  vaultParams: string;
  delegatorIndex: number;
  delegatorParams: string;
  withSlasher: boolean;
  slasherIndex: number;
  slasherParams: string;
};

export enum DelegatorType {
  NETWORK_RESTAKE = 0,
  FULL_RESTAKE = 1,
  OPERATOR_SPECIFIC = 2,
}
