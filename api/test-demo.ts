import { BigNumber, ethers } from "ethers";
import {
  OPERATOR_ADDRESS,
  OPERATOR_NETWORK_OPT_IN_SERVICE_ADDRESS,
  OPERATOR_PRIVATE_KEY,
  OPERATOR_REGISTRY_ADDRESS,
  OPERATOR_VAULT_OPT_IN_SERVICE_ADDRESS,
  OWNER_ADDRESS,
  VAULT_ADDRESS,
} from "./config";
import { OptInAPI } from "./opt_in/opt_in";
import { OperatorRegistryAPI } from "./registry/operator_registry/operator_registry";
import { MIDDLEWARE_ABI } from "./middleware/middleware_abi";
import { TOKEN_ABI } from "./token/token_abi";
import { VaultAPI } from "./vault/vault";

const provider = new ethers.providers.JsonRpcProvider("http://127.0.0.1:8545");

const operatorWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, provider);
const ownerWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, provider);

const operatorRegistry = new OperatorRegistryAPI(
  OPERATOR_REGISTRY_ADDRESS,
  operatorWallet
);
const vaultOptIn = new OptInAPI(
  OPERATOR_VAULT_OPT_IN_SERVICE_ADDRESS,
  operatorWallet
);
const networkOptIn = new OptInAPI(
  OPERATOR_NETWORK_OPT_IN_SERVICE_ADDRESS,
  operatorWallet
);
const vault = new VaultAPI(VAULT_ADDRESS, operatorWallet);

const middlewareAddress = "";

const middleware = new ethers.Contract(
  middlewareAddress,
  MIDDLEWARE_ABI,
  ownerWallet
);
const tokenAddress = "";

const token = new ethers.Contract(tokenAddress, TOKEN_ABI, ownerWallet);

async function registerOperator(vaultAddress: string, networkAddress: string) {
  try {
    await operatorRegistry.registerOperator();
    await vaultOptIn.optIn(vaultAddress);
    await networkOptIn.optIn(networkAddress);
  } catch (e) {
    console.log(e);
  }
}

async function registerOperatorToMiddleware(
  vaultAddress: string,
  operatorAddress: string
) {
  try {
    const tx = await middleware.registerOperator(operatorAddress);
    await tx.wait();

    const tx2 = await middleware.registerVault(vaultAddress);
    await tx2.wait();
  } catch (e) {
    console.log(e);
  }
}

async function depositToVault(
  vaultAddress: string,
  operatorAddress: string,
  amount: BigNumber
) {
  try {
    const tx = await token.approve(vaultAddress, amount);
    await tx.wait();

    await vault.deposit(operatorAddress, amount);
  } catch (e) {
    console.log(e);
  }
}

const DEFAULT_AMOUNT = ethers.BigNumber.from(1000);

// Here owner address is network address
registerOperator(VAULT_ADDRESS, OWNER_ADDRESS);

registerOperatorToMiddleware(VAULT_ADDRESS, OPERATOR_ADDRESS);

depositToVault(VAULT_ADDRESS, OPERATOR_ADDRESS, DEFAULT_AMOUNT);
