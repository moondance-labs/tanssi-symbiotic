import { ethers } from "ethers";
import {
  NETWORK_ADDRESS,
  OPERATOR_ADDRESS,
  OPERATOR_NETWORK_OPT_IN_SERVICE_ADDRESS,
  OPERATOR_PRIVATE_KEY,
  OPERATOR_VAULT_OPT_IN_SERVICE_ADDRESS,
  VAULT_ADDRESS,
} from "../../config";
import { OptInAPI } from "../../opt_in/opt_in";

describe("OptIn", () => {
  let vaultOptIn: OptInAPI;
  let networkOptIn: OptInAPI;

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const operatorWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, provider);

    vaultOptIn = new OptInAPI(
      OPERATOR_VAULT_OPT_IN_SERVICE_ADDRESS,
      operatorWallet
    );
    networkOptIn = new OptInAPI(
      OPERATOR_NETWORK_OPT_IN_SERVICE_ADDRESS,
      operatorWallet
    );
  });

  test("Nonces", async () => {
    const vaultNonce = await vaultOptIn.nonces(OPERATOR_ADDRESS, VAULT_ADDRESS);
    expect(vaultNonce.toNumber()).toBe(0);

    const networkNonce = await networkOptIn.nonces(
      OPERATOR_ADDRESS,
      NETWORK_ADDRESS
    );
    expect(networkNonce.toNumber()).toBe(0);
  });

  test("Opt Operator In", async () => {
    await vaultOptIn.optIn(VAULT_ADDRESS);
    await networkOptIn.optIn(NETWORK_ADDRESS);
  });

  test("Is Opted In", async () => {
    const isVaultOptedIn = await vaultOptIn.isOptedIn(
      OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(isVaultOptedIn).toBe(true);

    const isNetworkOptedIn = await networkOptIn.isOptedIn(
      OPERATOR_ADDRESS,
      NETWORK_ADDRESS
    );
    expect(isNetworkOptedIn).toBe(true);
  });

  test("Nonces", async () => {
    const vaultNonce = await vaultOptIn.nonces(OPERATOR_ADDRESS, VAULT_ADDRESS);
    expect(vaultNonce.toNumber()).toBe(1);

    const networkNonce = await networkOptIn.nonces(
      OPERATOR_ADDRESS,
      NETWORK_ADDRESS
    );
    expect(networkNonce.toNumber()).toBe(1);
  });

  test("Opt Operator Out", async () => {
    await vaultOptIn.optOut(VAULT_ADDRESS);
    await networkOptIn.optOut(NETWORK_ADDRESS);
  });

  test("Is Opted In", async () => {
    const isVaultOptedIn = await vaultOptIn.isOptedIn(
      OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(isVaultOptedIn).toBe(false);

    const isNetworkOptedIn = await networkOptIn.isOptedIn(
      OPERATOR_ADDRESS,
      NETWORK_ADDRESS
    );
    expect(isNetworkOptedIn).toBe(false);
  });
});
