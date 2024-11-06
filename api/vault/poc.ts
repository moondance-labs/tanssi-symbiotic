import { Contract, ethers } from "ethers";
import { OWNER_PRIVATE_KEY } from "../config";
import { VaultAPI } from "./vault";
import { COLLATERAL_ABI } from "./collateral_abi";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(OWNER_PRIVATE_KEY, jsonProvider);

const VAULT_ADDRESS = "0x6692129Ec011A54E60d948b738c8157237589224";
const COLLATERAL_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

const collateralContract = new Contract(
  COLLATERAL_ADDRESS,
  COLLATERAL_ABI,
  wallet
);

const vault = new VaultAPI(VAULT_ADDRESS, wallet);

vault.slasher().then((slasher) => {
  console.log("Slasher: ", slasher);
});

vault.owner().then((owner) => {
  console.log("Owner: ", owner);
});

vault.epochDuration().then((epochDuration) => {
  console.log("Epoch Duration: ", epochDuration.toString());
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

collateralContract.balanceOf(wallet.address).then((balance) => {
  console.log("Collateral Balance: ", balance.toString());
});

const approveAndDeposit = async () => {
  await collateralContract.approve(VAULT_ADDRESS, ethers.BigNumber.from(1000));
  const { depositedAmount, mintedShares } = await vault.deposit(
    wallet.address,
    ethers.BigNumber.from(1000)
  );
  console.log(
    "Deposit Transaction. Deposited Amount: ",
    depositedAmount.toString(),
    " Minted Shares: ",
    mintedShares.toString()
  );
};

approveAndDeposit().then(() => {
  vault.withdraw(wallet.address, ethers.BigNumber.from(1000)).then((tx) => {
    console.log(
      "Withdraw Transaction. Burned Shares: ",
      tx.burnedShares.toString(),
      " Minted Shares: ",
      tx.mintedShares.toString()
    );
  });
});
