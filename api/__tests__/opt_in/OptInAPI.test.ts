// OperatorRegistryAPI.test.ts
import { ethers } from "ethers";
import { OPERATOR_PRIVATE_KEY } from "../../config";
import { OptInAPI } from "../../opt_in/opt_in";

describe("OptIn", () => {
  let vaultOptIn: OptInAPI;
  let networkOptIn: OptInAPI;

  const VAULT_OPT_IN_CONTRACT_ADDRESS =
    "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318";
  const NETWORK_OPT_IN_CONTRACT_ADDRESS =
    "0x610178dA211FEF7D417bC0e6FeD39F05609AD788";

  const VAULT_ADDRESS = "0x6Af8D50A91d39D71137FAd18EB7F4f988c0B70aa";

  const DEFAULT_OPERATOR_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
  const DEFAULT_NETWORK_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );

    const operatorWallet = new ethers.Wallet(OPERATOR_PRIVATE_KEY, provider);

    vaultOptIn = new OptInAPI(VAULT_OPT_IN_CONTRACT_ADDRESS, operatorWallet);
    networkOptIn = new OptInAPI(
      NETWORK_OPT_IN_CONTRACT_ADDRESS,
      operatorWallet
    );
  });

  test("Nonces", async () => {
    const vaultNonce = await vaultOptIn.nonces(
      DEFAULT_OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(vaultNonce.toNumber()).toBe(0);

    const networkNonce = await networkOptIn.nonces(
      DEFAULT_OPERATOR_ADDRESS,
      DEFAULT_NETWORK_ADDRESS
    );
    expect(networkNonce.toNumber()).toBe(0);
  });

  test("Opt Operator In", async () => {
    await vaultOptIn.optIn(VAULT_ADDRESS);
    await networkOptIn.optIn(DEFAULT_NETWORK_ADDRESS);
  });

  test("Is Opted In", async () => {
    const isVaultOptedIn = await vaultOptIn.isOptedIn(
      DEFAULT_OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(isVaultOptedIn).toBe(true);

    const isNetworkOptedIn = await networkOptIn.isOptedIn(
      DEFAULT_OPERATOR_ADDRESS,
      DEFAULT_NETWORK_ADDRESS
    );
    expect(isNetworkOptedIn).toBe(true);
  });

  test("Nonces", async () => {
    const vaultNonce = await vaultOptIn.nonces(
      DEFAULT_OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(vaultNonce.toNumber()).toBe(1);

    const networkNonce = await networkOptIn.nonces(
      DEFAULT_OPERATOR_ADDRESS,
      DEFAULT_NETWORK_ADDRESS
    );
    expect(networkNonce.toNumber()).toBe(1);
  });

  test("Opt Operator Out", async () => {
    await vaultOptIn.optOut(VAULT_ADDRESS);
    await networkOptIn.optOut(DEFAULT_NETWORK_ADDRESS);
  });

  test("Is Opted In", async () => {
    const isVaultOptedIn = await vaultOptIn.isOptedIn(
      DEFAULT_OPERATOR_ADDRESS,
      VAULT_ADDRESS
    );
    expect(isVaultOptedIn).toBe(false);

    const isNetworkOptedIn = await networkOptIn.isOptedIn(
      DEFAULT_OPERATOR_ADDRESS,
      DEFAULT_NETWORK_ADDRESS
    );
    expect(isNetworkOptedIn).toBe(false);
  });
});
