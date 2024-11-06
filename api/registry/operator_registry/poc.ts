import { ethers } from "ethers";
import { OPERATOR_PRIVATE_KEY } from "../../config";
import { OperatorRegistryAPI } from "./operator_registry";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, jsonProvider);

const OPERATOR_REGISTRY_ADDRESS = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707";

const operatorRegistry = new OperatorRegistryAPI(
  OPERATOR_REGISTRY_ADDRESS,
  wallet
);

operatorRegistry
  .registerOperator()
  .then(() => {
    console.log("Operator was registered successfully");
  })
  .catch((error) => {
    console.error("Failed to register operator: ", error);
  });

operatorRegistry.totalEntities().then((totalEntities) => {
  console.log("Total Entities: ", totalEntities.toString());
});
