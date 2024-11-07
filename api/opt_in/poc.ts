import { ethers } from "ethers";
import { NETWORK_PRIVATE_KEY, OPERATOR_PRIVATE_KEY } from "../config";
import { OptInAPI } from "./opt_in";

const jsonProvider = new ethers.providers.JsonRpcProvider(
  "http://127.0.0.1:8545"
);

const operatorWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, jsonProvider);
const networkWallet = new ethers.Wallet(NETWORK_PRIVATE_KEY, jsonProvider);
const VAULT_OPT_IN_CONTRACT_ADDRESS =
  "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
const NETWORK_OPT_IN_CONTRACT_ADDRESS =
  "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";
const VAULT_ADDRESS = "0x6Af8D50A91d39D71137FAd18EB7F4f988c0B70aa";

const vaultOptIn = new OptInAPI(VAULT_OPT_IN_CONTRACT_ADDRESS, operatorWallet);
const networkOptIn = new OptInAPI(
  NETWORK_OPT_IN_CONTRACT_ADDRESS,
  operatorWallet
);

const optOperatorIn = async () => {
  await vaultOptIn.optIn(VAULT_ADDRESS);
  await networkOptIn.optIn(networkWallet.address);
  console.log("Opted in successfully");
};

const optOperatorOut = async () => {
  await vaultOptIn.optOut(VAULT_ADDRESS);
  await networkOptIn.optOut(networkWallet.address);
  console.log("Opted out successfully");
};
optOperatorIn().then(() => {
  optOperatorOut();
});
