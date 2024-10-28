import { ethers } from "ethers";
import { PRIVATE_KEY } from "../config";
import { FactoryAPI } from "./factory";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const contractAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

const factory = new FactoryAPI(contractAddress, wallet);

const MADE_UP_ADDRESS = "0xc1912fEE45d61C87Cc5EA59DaE31190FFFFf232d";

factory.blacklist(0).then(() => {
  console.log("Blacklisted Entity at index: 0");
});

factory.whitelist(MADE_UP_ADDRESS).then(() => {
  console.log("Whitelisted implementation: ", MADE_UP_ADDRESS);
});

factory.implementation(0).then((implementation) => {
  console.log("Implementation at index 0: ", implementation);
});
