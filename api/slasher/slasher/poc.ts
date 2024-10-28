import { ethers } from "ethers";
import { PRIVATE_KEY } from "../../config";
import { SlasherAPI } from "./slasher";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const contractAddress = "0xAc31FA0eB0089E32da44Fc31E1E0457A79Bf0977";

const slasher = new SlasherAPI(contractAddress, wallet);

//TODO: Rough implementation to get a subnetwork ID, still needs to be implemented properly
function createSubnetworkId(
  networkAddress: string,
  identifier: number
): string {
  // Convert address to bytes (remove '0x' and pad to 40 characters)
  const addressBytes = networkAddress.slice(2).padStart(40, "0");

  // Convert identifier to bytes (12 bytes = 24 characters for uint96)
  const identifierBytes = identifier.toString(16).padStart(24, "0");

  return "0x" + addressBytes + identifierBytes;
}

const networkAddress = "0x0c4BE2f0005ce23555782dffb9c2Daa04a521c88";
const networkIdentifier = 1;

const subnetworkId = createSubnetworkId(networkAddress, networkIdentifier);

const bytes32Value = ethers.utils.hexZeroPad(subnetworkId, 32);

slasher
  .cumulativeSlash({
    subnetwork: bytes32Value,
    operator: "0xF65B8FC22842CB9d3fD7c96C0dfD25122685E9B4",
  })
  .then((cumulativeSlash) => {
    console.log("Cumulative Slash: ", cumulativeSlash.toString());
  });

slasher
  .slash({
    subnetwork: bytes32Value,
    operator: "0xF65B8FC22842CB9d3fD7c96C0dfD25122685E9B4",
    captureTimestamp: 0,
    hints: "",
    amount: ethers.BigNumber.from(1000),
  })
  .then((slash) => {
    console.log("Slash: ", slash.toString());
  });
