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

export enum DelegatorType {
  NETWORK_RESTAKE = 0,
  FULL_RESTAKE = 1,
  OPERATOR_SPECIFIC = 2,
}