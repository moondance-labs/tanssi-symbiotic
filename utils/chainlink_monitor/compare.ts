import { ethers } from "ethers";
import { sendSlackAlert } from "./send_slack";
import { decodeOperatorsData } from "./decode_operators_data";
import { PRIVATE_KEY } from "./chainlink_monitor_slack_alert";

export async function compareWithMiddlewareData(
  middlewareContract: ethers.Contract,
  payload: string,
  timestamp: number,
  event: ethers.Event,
  provider: ethers.providers.Provider,
  shouldSendTx: boolean
): Promise<void> {
  const epoch = await middlewareContract.getEpochAtTs(timestamp);
  console.log("Epoch:", epoch.toString());

  try {
    // Get sorted operators from middleware
    // TODO Should use sortOperatorsByPower once Middleware is upgraded to latest
    const verifiedOperatorKeys = await middlewareContract.sortOperatorsByVaults(
      epoch
    );

    const {
      oracleOperatorKeys,
      operatorsCount,
      epoch: epochValue,
    } = decodeOperatorsData(payload);

    // Compare the data
    const comparisonResult = await compareOperatorsData(
      verifiedOperatorKeys,
      epoch,
      oracleOperatorKeys,
      epochValue,
      operatorsCount
    );

    if (!comparisonResult.match && "message" in comparisonResult) {
      console.log("Discrepancies found:", comparisonResult.message);

      // Send to Slack
      await sendSlackAlert({
        message: comparisonResult.message,
        blockNumber: event.blockNumber,
        timestamp,
        txHash: event.transactionHash,
      });

      // We only send the keys if its the latest epoch since we can't override the keys of past epochs
      if (shouldSendTx && PRIVATE_KEY !== undefined) {
        const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
        middlewareContract = middlewareContract.connect(wallet);
        console.log("Sending transaction to override latest operator keys...");
        const tx = await middlewareContract.sendCurrentOperatorsKeys();
        const message = `Sent transaction to override latest operator keys after finding tampered data.`;
        const receipt = await tx.wait();
        const blockData = await provider.getBlock(receipt.blockNumber);
        console.log("Transaction sent:", tx.hash);

        await sendSlackAlert({
          message: message,
          blockNumber: receipt.blockNumber,
          timestamp: blockData.timestamp,
          txHash: tx.hash,
          shouldSendTx,
          header: "✅ Transaction sent to override latest operator keys",
        });
      }
    }
  } catch (error) {
    console.error("Error comparing operator data:", error);
  }
}

export async function compareOperatorsData(
  sortedOperators: string[],
  epoch: number,
  operatorsKeysPayload: string[],
  epochPayload: number,
  operatorsCount: number
): Promise<
  | {
      match: boolean;
      message: string;
    }
  | {
      match: boolean;
      error?: string;
    }
> {
  try {
    let message = "";
    if (epoch !== epochPayload) {
      message = `Epoch mismatch: Middleware epoch ${epoch} vs Payload epoch ${epochPayload}`;
      return { match: false, message };
    }

    // Check length match
    if (sortedOperators.length !== operatorsKeysPayload.length) {
      message = `Length mismatch: Middleware length ${sortedOperators.length} vs Payload length ${operatorsKeysPayload.length}`;
      return { match: false, message };
    }

    if (
      sortedOperators.length !== operatorsCount ||
      operatorsKeysPayload.length !== operatorsCount ||
      sortedOperators.length !== operatorsKeysPayload.length
    ) {
      message = `Operators count mismatch: Middleware count ${sortedOperators.length} vs Payload count ${operatorsKeysPayload.length} vs Operators count ${operatorsCount}`;
      return { match: false, message };
    }

    // Check each element
    const differences: {
      [key: string]: {
        middleware: string;
        gateway: string;
      };
    } = {};

    let hasDiscrepancy = false;

    for (let i = 0; i < sortedOperators.length; i++) {
      if (sortedOperators[i] !== operatorsKeysPayload[i]) {
        hasDiscrepancy = true;
        differences[`index_${i}`] = {
          middleware: sortedOperators[i],
          gateway: operatorsKeysPayload[i],
        };
      }
    }

    message = `:warning: *Mismatch in Operators for Epoch ${epoch}* :warning:\n\n`;

    message += `The following discrepancies were found:\n\n`;
    for (const [key, diff] of Object.entries(differences)) {
      const index = key.replace("index_", "");
      message += `*At position ${index}:*\n`;
      message += `> *Middleware:* ${diff.middleware}\n`;
      message += `> *Gateway:* ${diff.gateway}\n\n`;
    }

    return {
      match: !hasDiscrepancy,
      message,
    };
  } catch (error) {
    console.error("Error decoding or comparing data:", error);
    return {
      match: false,
      error: `Error decoding or comparing data: ${(error as Error).message}`,
    };
  }
}
