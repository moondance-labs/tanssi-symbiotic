import { ethers } from "ethers";
import { PRIVATE_KEY } from "../../config";
import { VetoSlasherAPI } from "./veto_slasher";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const contractAddress = "0x5011763628835226A7bDd69a370BF0bA44fbbb4A";

const vetoSlasher = new VetoSlasherAPI(contractAddress, wallet);

vetoSlasher.slashRequestsLength().then((length) => {
  console.log("Slash requests length: ", length.toString());
});

vetoSlasher
  .requestSlash({
    subnetwork: "0x",
    operator: "0x",
    amount: ethers.BigNumber.from(1000),
    hints: "",
    captureTimestamp: 0,
  })
  .then((slashIndex) => {
    console.log("Request Slash index: ", slashIndex);
  });
