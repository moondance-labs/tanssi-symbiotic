import { Contract, ethers } from "ethers";
import { PRIVATE_KEY } from "../config";
import { VaultAPI } from "./vault";
import { COLLATERAL_ABI } from "./collateral_abi";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const wallet = new ethers.Wallet(PRIVATE_KEY, jsonProvider);

const CONTRACT_ADDRESS = "0xD5FE47FaB349E52a4648B7D9c5b42364AAF375ae";
const COLLATERAL_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

const collateralContract = new Contract(
  COLLATERAL_ADDRESS,
  COLLATERAL_ABI,
  wallet
);

const vault = new VaultAPI(CONTRACT_ADDRESS, wallet);

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

collateralContract.balanceOf(wallet.address).then((balance) => {
  console.log("Collateral Balance: ", balance.toString());
});

const approveAndDeposit = async () => {
  await collateralContract.approve(
    CONTRACT_ADDRESS,
    ethers.BigNumber.from(1000)
  );
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
