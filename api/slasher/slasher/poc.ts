import { ethers } from "ethers";
import { NETWORK_PRIVATE_KEY, OWNER_PRIVATE_KEY } from "../../config";
import { SlasherAPI } from "./slasher";
import { subnetwork } from "../../utils";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, jsonProvider);
const networkWallet = new ethers.Wallet(NETWORK_PRIVATE_KEY, jsonProvider);
const SLASHER_ADDRESS = "0xAc31FA0eB0089E32da44Fc31E1E0457A79Bf0977";

const OPERATOR_ADDRESS = "0xF65B8FC22842CB9d3fD7c96C0dfD25122685E9B4";
const slasher = new SlasherAPI(SLASHER_ADDRESS, wallet);

const subNetwork = subnetwork(networkWallet.address, 0);
console.log("Subnetwork: ", subNetwork);

slasher
  .cumulativeSlash({
    subnetwork: subNetwork,
    operator: OPERATOR_ADDRESS,
  })
  .then((cumulativeSlash) => {
    console.log("Cumulative Slash: ", cumulativeSlash.toString());
  });

// This can be called only by middleware, leaving here for reference
slasher
  .slash({
    subnetwork: subNetwork,
    operator: OPERATOR_ADDRESS,
    captureTimestamp: Date.now(), //Calculate proper timestamp to be:
    // Time.timestamp() + vetoDuration − IVault(vault).epochDuration() ≤ captureTimestamp < Time.timestamp()
    hints: "0x",
    amount: ethers.BigNumber.from(1000),
  })
  .then((slash) => {
    console.log("Slash: ", slash.toString());
  });
