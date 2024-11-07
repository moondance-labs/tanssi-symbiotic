import { ethers } from "ethers";
import { OWNER_PRIVATE_KEY } from "../../config";
import { FactoryAPI } from "./factory";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, jsonProvider);

const factoryAddress = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

const factory = new FactoryAPI(factoryAddress, wallet);

const RANDOM_VAULT_ADDRESS = "0xc1912fEE45d61C87Cc5EA59DaE31190FFFFf232d";

factory.blacklist(0).then(() => {
  console.log("Blacklisted Entity at index: 0");
});

factory.whitelist(RANDOM_VAULT_ADDRESS).then(() => {
  console.log("Whitelisted implementation: ", RANDOM_VAULT_ADDRESS);
});

factory.implementation(0).then((implementation) => {
  console.log("Implementation at index 0: ", implementation);
});
