import axios from "axios";
import { SLACK_WEBHOOK_URL } from "./chainlink_monitor_slack_alert";

type AlertEventData = {
  message: string;
  timestamp: number;
  blockNumber: number;
  txHash: string;
  shouldSendTx?: boolean;
  header?: string;
};

export async function sendSlackAlert(eventData: AlertEventData): Promise<void> {
  try {
    const message = {
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text:
              eventData.header ??
              "🚨 Mismatch found between Chainlink Automation and On-Chain sorting",
            emoji: true,
          },
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `${eventData.message}`,
          },
        },
        ...(eventData.shouldSendTx
          ? [
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*Etherscan Link:*\n<https://etherscan.io/tx/${eventData.txHash}|View Transaction on Etherscan>`,
                },
              },
            ]
          : []),
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Block Number:*\n${eventData.blockNumber}`,
          },
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Timestamp:*\n${new Date(
              eventData.timestamp * 1000
            ).toISOString()}`,
          },
        },
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*Transaction:*\n\`${eventData.txHash}\``,
          },
        },
        {
          type: "divider",
        },
      ],
    };

    await axios.post(SLACK_WEBHOOK_URL as string, message);
    console.log("Alert sent to Slack successfully");
  } catch (error) {
    console.error("Failed to send Slack alert:", error);
  }
}
