export const SLASHER_ABI = [
  {
    type: "constructor",
    inputs: [
      {
        name: "vaultFactory",
        type: "address",
        internalType: "address",
      },
      {
        name: "networkMiddlewareService",
        type: "address",
        internalType: "address",
      },
      {
        name: "slasherFactory",
        type: "address",
        internalType: "address",
      },
      { name: "entityType", type: "uint64", internalType: "uint64" },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "BURNER_GAS_LIMIT",
    inputs: [],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "BURNER_RESERVE",
    inputs: [],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "FACTORY",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "NETWORK_MIDDLEWARE_SERVICE",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "TYPE",
    inputs: [],
    outputs: [{ name: "", type: "uint64", internalType: "uint64" }],
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
    name: "cumulativeSlash",
    inputs: [
      { name: "subnetwork", type: "bytes32", internalType: "bytes32" },
      { name: "operator", type: "address", internalType: "address" },
    ],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "cumulativeSlashAt",
    inputs: [
      { name: "subnetwork", type: "bytes32", internalType: "bytes32" },
      { name: "operator", type: "address", internalType: "address" },
      { name: "timestamp", type: "uint48", internalType: "uint48" },
      { name: "hint", type: "bytes", internalType: "bytes" },
    ],
    outputs: [{ name: "", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "initialize",
    inputs: [{ name: "data", type: "bytes", internalType: "bytes" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "isBurnerHook",
    inputs: [],
    outputs: [{ name: "", type: "bool", internalType: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "latestSlashedCaptureTimestamp",
    inputs: [
      { name: "subnetwork", type: "bytes32", internalType: "bytes32" },
      { name: "operator", type: "address", internalType: "address" },
    ],
    outputs: [{ name: "value", type: "uint48", internalType: "uint48" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "slash",
    inputs: [
      { name: "subnetwork", type: "bytes32", internalType: "bytes32" },
      { name: "operator", type: "address", internalType: "address" },
      { name: "amount", type: "uint256", internalType: "uint256" },
      {
        name: "captureTimestamp",
        type: "uint48",
        internalType: "uint48",
      },
      { name: "hints", type: "bytes", internalType: "bytes" },
    ],
    outputs: [
      {
        name: "slashedAmount",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "slashableStake",
    inputs: [
      { name: "subnetwork", type: "bytes32", internalType: "bytes32" },
      { name: "operator", type: "address", internalType: "address" },
      {
        name: "captureTimestamp",
        type: "uint48",
        internalType: "uint48",
      },
      { name: "hints", type: "bytes", internalType: "bytes" },
    ],
    outputs: [{ name: "amount", type: "uint256", internalType: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "staticDelegateCall",
    inputs: [
      { name: "target", type: "address", internalType: "address" },
      { name: "data", type: "bytes", internalType: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "vault",
    inputs: [],
    outputs: [{ name: "", type: "address", internalType: "address" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "Initialized",
    inputs: [
      {
        name: "version",
        type: "uint64",
        indexed: false,
        internalType: "uint64",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Slash",
    inputs: [
      {
        name: "subnetwork",
        type: "bytes32",
        indexed: true,
        internalType: "bytes32",
      },
      {
        name: "operator",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "slashedAmount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "captureTimestamp",
        type: "uint48",
        indexed: false,
        internalType: "uint48",
      },
    ],
    anonymous: false,
  },
  { type: "error", name: "CheckpointUnorderedInsertion", inputs: [] },
  { type: "error", name: "InsufficientBurnerGas", inputs: [] },
  { type: "error", name: "InsufficientSlash", inputs: [] },
  { type: "error", name: "InvalidCaptureTimestamp", inputs: [] },
  { type: "error", name: "InvalidInitialization", inputs: [] },
  { type: "error", name: "NoBurner", inputs: [] },
  { type: "error", name: "NotInitialized", inputs: [] },
  { type: "error", name: "NotInitializing", inputs: [] },
  { type: "error", name: "NotNetworkMiddleware", inputs: [] },
  { type: "error", name: "NotVault", inputs: [] },
  { type: "error", name: "ReentrancyGuardReentrantCall", inputs: [] },
  {
    type: "error",
    name: "SafeCastOverflowedUintDowncast",
    inputs: [
      { name: "bits", type: "uint8", internalType: "uint8" },
      { name: "value", type: "uint256", internalType: "uint256" },
    ],
  },
];
