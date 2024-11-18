export const VAULT_CONFIGURATOR_ABI = [
  {
    type: "constructor",
    inputs: [
      {
        name: "vaultFactory",
        type: "address",
        internalType: "address",
      },
      {
        name: "delegatorFactory",
        type: "address",
        internalType: "address",
      },
      {
        name: "slasherFactory",
        type: "address",
        internalType: "address",
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "DELEGATOR_FACTORY",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "SLASHER_FACTORY",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "VAULT_FACTORY",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "create",
    inputs: [
      {
        name: "params",
        type: "tuple",
        internalType: "struct IVaultConfigurator.InitParams",
        components: [
          { name: "version", type: "uint64", internalType: "uint64" },
          { name: "owner", type: "address", internalType: "address" },
          { name: "vaultParams", type: "bytes", internalType: "bytes" },
          {
            name: "delegatorIndex",
            type: "uint64",
            internalType: "uint64",
          },
          {
            name: "delegatorParams",
            type: "bytes",
            internalType: "bytes",
          },
          { name: "withSlasher", type: "bool", internalType: "bool" },
          {
            name: "slasherIndex",
            type: "uint64",
            internalType: "uint64",
          },
          {
            name: "slasherParams",
            type: "bytes",
            internalType: "bytes",
          },
        ],
      },
    ],
    outputs: [
      { name: "vault", type: "address", internalType: "address" },
      { name: "delegator", type: "address", internalType: "address" },
      { name: "slasher", type: "address", internalType: "address" },
    ],
    stateMutability: "nonpayable",
  },
];
