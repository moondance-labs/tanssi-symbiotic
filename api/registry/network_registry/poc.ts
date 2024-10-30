import { ethers } from "ethers";
import { NETWORK_PRIVATE_KEY } from "../../config";
import { NetworkRegistryAPI } from "./network_registry";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(NETWORK_PRIVATE_KEY, jsonProvider);

const contractAddress = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";

const networkRegistry = new NetworkRegistryAPI(contractAddress, wallet);

networkRegistry
  .registerNetwork()
  .then(() => {
    console.log("Network was registered successfully");
  })
  .catch((error) => {
    console.error("Failed to register operator: ", error);
  });

networkRegistry.totalEntities().then((totalEntities) => {
  console.log("Total Entities: ", totalEntities.toString());
});
