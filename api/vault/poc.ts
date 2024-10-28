import { ethers } from "ethers";
import { PRIVATE_KEY } from "../config";
import { VaultAPI } from "./vault";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const contractAddress = "0x0c4BE2f0005ce23555782dffb9c2Daa04a521c88";

const vault = new VaultAPI(contractAddress, wallet);

vault.getSlasher().then((slasher) => {
  console.log("Slasher: ", slasher);
});

vault.owner().then((owner) => {
  console.log("Owner: ", owner);
});

vault.isInitialized().then((isInitialized) => {
  console.log("Initialized: ", isInitialized);
});

vault.totalStake().then((totalStake) => {
  console.log("Total Stake: ", totalStake.toString());
});

vault.activeBalanceOf(wallet.address).then((balance) => {
  console.log("Active Balance: ", balance.toString());
});

vault.deposit(wallet.address, ethers.BigNumber.from(1000)).then((tx) => {
  console.log(
    "Deposit Transaction. Deposited Amount: ",
    tx.depositedAmount.toString(),
    " Minted Shares: ",
    tx.mintedShares.toString()
  );
});
