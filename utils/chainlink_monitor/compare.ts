import { ethers } from "ethers";
import { sendSlackAlert } from "./send_slack";
import { decodeOperatorsData } from "./decode_operators_data";

export async function compareWithMiddlewareData(
  middlewareContract: ethers.Contract,
  payload: string,
  timestamp: number,
  event: ethers.Event
): Promise<void> {
  const epoch = await middlewareContract.getEpochAtTs(timestamp);
  console.log("Epoch:", epoch.toString());
  try {
    // Get sorted operators from middleware
    // TODO Should use sortOperatorsByPower once Middleware is upgraded to latest
    const sortedOperators = await middlewareContract.sortOperatorsByVaults(
      epoch
    );

    const {
      operatorsKeys,
      operatorsCount,
      epoch: epochValue,
    } = decodeOperatorsData(payload);

    const operatorsArray = [...sortedOperators];

    operatorsArray.push("0xNewOperatorAddressHere");
    operatorsArray.push("0xNewOperatorAddressHere");
    operatorsArray.push("0xNewOperatorAddressHere2");

    operatorsKeys.push("0x000000000000000000000000000000000000dEaD");
    operatorsKeys.push("0xNewOperatorAddressHere");
    operatorsKeys.push("0xNewOperatorAddressHere3");

    // Compare the data
    const comparisonResult = await compareOperatorsData(
      operatorsArray,
      epoch,
      operatorsKeys,
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
    if (epoch !== epochPayload) {
      return { match: false, error: "Epoch mismatch" };
    }

    // Check length match
    if (sortedOperators.length !== operatorsKeysPayload.length) {
      return { match: false, error: "Length mismatch" };
    }

    if (
      sortedOperators.length !== operatorsCount ||
      operatorsKeysPayload.length !== operatorsCount
    ) {
      return { match: false, error: "Operators count mismatch" };
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

    let message = `:warning: *Mismatch in Operators for Epoch ${epoch}* :warning:\n\n`;

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
