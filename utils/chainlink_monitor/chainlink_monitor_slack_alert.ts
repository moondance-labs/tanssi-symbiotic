import { ethers } from "ethers";
import * as dotenv from "dotenv";
import { compareWithMiddlewareData } from "./compare";

dotenv.config();

// Environment variables
const RPC_URL = process.env.RPC_URL;
const GATEWAY_ADDRESS = process.env.GATEWAY_ADDRESS;
const MIDDLEWARE_ADDRESS = process.env.MIDDLEWARE_ADDRESS;
export const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

// Gateway ABI - just the parts we need for the event
const gatewayAbi = [
  "event OperatorsDataCreated(uint256 indexed validatorsCount, bytes payload)",
];

// Middleware ABI - just the parts we need for functions
const middlewareAbi = [
  {
    inputs: [{ internalType: "uint48", name: "epoch", type: "uint48" }],
    stateMutability: "view",
    type: "function",
    name: "sortOperatorsByPower",
    outputs: [
      {
        internalType: "bytes32[]",
        name: "sortedKeys",
        type: "bytes32[]",
      },
    ],
  },
  {
    type: "function",
    name: "getEpochAtTs",
    inputs: [{ name: "timestamp", type: "uint48", internalType: "uint48" }],
    outputs: [{ name: "epoch", type: "uint48", internalType: "uint48" }],
    stateMutability: "view",
  },
  // TODO take out. Should use sortOperatorsByPower once Middleware is upgraded to latest
  {
    inputs: [{ internalType: "uint48", name: "epoch", type: "uint48" }],
    name: "sortOperatorsByVaults",
    outputs: [
      { internalType: "bytes32[]", name: "sortedKeys", type: "bytes32[]" },
    ],
    stateMutability: "view",
    type: "function",
  },
];

async function main(): Promise<void> {
  if (
    !RPC_URL ||
    !GATEWAY_ADDRESS ||
    !SLACK_WEBHOOK_URL ||
    !MIDDLEWARE_ADDRESS
  ) {
    throw new Error(
      "Missing required environment variables. Check your .env file."
    );
  }

  // Parse command line arguments for lookback time in seconds
  const lookbackSeconds = parseLookbackArgument();

  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

  // Gateway contract instance
  const gatewayContract = new ethers.Contract(
    GATEWAY_ADDRESS,
    gatewayAbi,
    provider
  );

  // Middleware contract instance
  const middlewareContract = new ethers.Contract(
    MIDDLEWARE_ADDRESS,
    middlewareAbi,
    provider
  );

  // If lookback is specified, first query historical events
  if (lookbackSeconds > 0) {
    await queryHistoricalEvents(
      provider,
      gatewayContract,
      middlewareContract,
      lookbackSeconds
    );
  }

  console.log(`Monitoring events from Gateway at ${GATEWAY_ADDRESS}...`);

  // Listen for OperatorsDataCreated events
  gatewayContract.on(
    "OperatorsDataCreated",
    async (
      validatorsCount: ethers.BigNumber,
      payload: string,
      event: ethers.Event
    ) => {
      const blockNumber = event.blockNumber;
      const txHash = event.transactionHash;

      console.log(`
      Event detected at block ${blockNumber}
      Transaction: ${txHash}
      Validators Count: ${validatorsCount.toString()}
      Payload: ${payload}
    `);
      const currentBlockData = await provider.getBlock(event.blockNumber);
      const timestamp = currentBlockData.timestamp;

      await compareWithMiddlewareData(
        middlewareContract,
        payload,
        timestamp,
        event
      );
    }
  );
}

// Parse command line argument for lookback time
function parseLookbackArgument(): number {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    return 0; // Default: no lookback
  }

  const lookbackSeconds = parseInt(args[1], 10);
  if (isNaN(lookbackSeconds) || lookbackSeconds < 0) {
    console.log("Invalid lookback time. Using default (0 seconds).");
    return 0;
  }

  console.log(`Looking back ${lookbackSeconds} seconds for missed events...`);
  return lookbackSeconds;
}

// Query historical events based on lookback time
async function queryHistoricalEvents(
  provider: ethers.providers.JsonRpcProvider,
  gatewayContract: ethers.Contract,
  middlewareContract: ethers.Contract,
  lookbackSeconds: number
): Promise<void> {
  try {
    // Get current block
    const currentBlock = await provider.getBlockNumber();

    // Estimate starting block based on average block time (13 seconds for Ethereum)
    const averageBlockTime = 13; // seconds
    const blocksToLookBack = Math.ceil(lookbackSeconds / averageBlockTime);
    const fromBlock = Math.max(0, currentBlock - blocksToLookBack);

    console.log(
      `Querying for historical events from block ${fromBlock} to ${currentBlock}...`
    );

    // Query for past events
    const filter = gatewayContract.filters.OperatorsDataCreated();
    const events = await gatewayContract.queryFilter(
      filter,
      fromBlock,
      currentBlock
    );

    console.log(
      `Found ${events.length} historical events, processing them now...`
    );

    // Process each event
    for (const event of events) {
      const currentBlockData = await provider.getBlock(event.blockNumber);
      const timestamp = currentBlockData.timestamp;

      // Extract event arguments
      const args = event.args;
      if (!args) continue;

      const [validatorsCount, payload] = args;

      // Only process events from our lookback window
      console.log(`
          Historical event found at block ${event.blockNumber}
          Transaction: ${event.transactionHash}
          Validators Count: ${validatorsCount.toString()}
          Payload: ${payload}
        `);

      await compareWithMiddlewareData(
        middlewareContract,
        payload,
        timestamp,
        event
      );
    }

    console.log("Historical event processing complete.");
  } catch (error) {
    console.error("Error processing historical events:", error);
  }
}

// Error handling for the main function
main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
