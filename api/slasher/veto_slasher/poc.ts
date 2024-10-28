import { ethers } from "ethers";
import { PRIVATE_KEY } from "../../config";
import { VetoSlasherAPI } from "./veto_slasher";
import { VETO_SLASHER_ABI } from "./veto_slasher_abi";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const contractAddress = "0x5011763628835226A7bDd69a370BF0bA44fbbb4A";

const vetoSlasher = new VetoSlasherAPI(contractAddress, wallet);

// function createSubnetworkId(
//   networkAddress: string,
//   identifier: number
// ): string {
//   // Convert address to bytes (remove '0x' and pad to 40 characters)
//   const addressBytes = networkAddress.slice(2).padStart(40, "0");

//   // Convert identifier to bytes (12 bytes = 24 characters for uint96)
//   const identifierBytes = identifier.toString(16).padStart(24, "0");

//   // Concatenate and return with '0x' prefix
//   return "0x" + addressBytes + identifierBytes;
// }

// const networkAddress = "0x0c4BE2f0005ce23555782dffb9c2Daa04a521c88";
// const networkIdentifier = 1; // This should be your actual network identifier

// const subnetworkId = createSubnetworkId(networkAddress, networkIdentifier);

// const bytes32Value = ethers.utils.hexZeroPad(subnetworkId, 32);

// // vetoSlasher
// //   .cumulativeSlash({
// //     subnetwork: bytes32Value,
// //     operator: "0xF65B8FC22842CB9d3fD7c96C0dfD25122685E9B4",
// //   })
// //   .then((cumulativeSlash) => {
// //     console.log("Cumulative Slash: ", cumulativeSlash.toString());
// //   });

// // vetoSlasher.slashRequests(0).then((slashRequest) => {
// //   console.log("Slash request: ", slashRequest);
// // });

vetoSlasher.slashRequestsLength().then((length) => {
  console.log("Slash requests length: ", length.toString());
});

// // vetoSlasher.setResolver(0, wallet.address, "").then((tx) => {
// //   console.log("Set resolver tx: ", tx.transactionHash);
// // });
