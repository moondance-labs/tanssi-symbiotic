import { ethers } from "ethers";
import { VaultAPI } from "../../vault/vault";
import {
  COLLATERAL_ADDRESS,
  ONE_DAY,
  OWNER_ADDRESS,
  OWNER_PRIVATE_KEY,
  VAULT_ADDRESS,
  ZERO_ADDRESS,
} from "../../config";
import { COLLATERAL_ABI } from "../../vault/collateral_abi";

describe("VaultAPI", () => {
  let vault: VaultAPI;
  let collateralContract: ethers.Contract;
  const DEFAULT_AMOUNT = ethers.BigNumber.from(1000);

  beforeAll(async () => {
    const provider = new ethers.providers.JsonRpcProvider(
      "http://127.0.0.1:8545"
    );
    const ownerWallet = new ethers.Wallet(OWNER_PRIVATE_KEY, provider);
    vault = new VaultAPI(VAULT_ADDRESS, ownerWallet);

    collateralContract = new ethers.Contract(
      COLLATERAL_ADDRESS,
      COLLATERAL_ABI,
      ownerWallet
    );
  });

  test("owner", async () => {
    await expect(vault.owner()).resolves.toBe(OWNER_ADDRESS);
  });

  test("slasher", async () => {
    await expect(vault.slasher()).resolves.toBe(ZERO_ADDRESS);
  });

  test("epochDuration", async () => {
    const epochDuration = await vault.epochDuration();
    expect(epochDuration).toEqual(ONE_DAY * 12);
  });

  test("isInitialized", async () => {
    const isInitialized = await vault.isInitialized();
    expect(isInitialized).toBe(true);
  });

  test("totalStake", async () => {
    const totalStake = await vault.totalStake();
    expect(totalStake.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("activeBalanceOf", async () => {
    const activeBalanceOf = await vault.activeBalanceOf(OWNER_ADDRESS);
    expect(activeBalanceOf.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("approveAndDeposit", async () => {
    await collateralContract.approve(VAULT_ADDRESS, DEFAULT_AMOUNT);

    const { depositedAmount, mintedShares } = await vault.deposit(
      OWNER_ADDRESS,
      DEFAULT_AMOUNT
    );
    expect(depositedAmount.toNumber()).toBeGreaterThan(0);
    expect(mintedShares.toNumber()).toBeGreaterThan(0);
  });

  test("withdraw", async () => {
    const { burnedShares, mintedShares } = await vault.withdraw(
      OWNER_ADDRESS,
      DEFAULT_AMOUNT
    );
    expect(burnedShares.toNumber()).toBeGreaterThan(0);
    expect(mintedShares.toNumber()).toBeGreaterThan(0);
  });

  test("depositLimit", async () => {
    const depositLimit = await vault.depositLimit();
    expect(depositLimit.toNumber()).toBeGreaterThanOrEqual(0);
  });

  test("isDelegatorInitialized", async () => {
    const isDelegatorInitialized = await vault.isDelegatorInitialized();
    expect(isDelegatorInitialized).toBe(true);
  });

  test("setDepositWhitelist", async () => {
    await expect(vault.setDepositWhitelist(true)).resolves.not.toThrow();
  });

  test("setDepositorWhitelistStatus", async () => {
    await expect(
      vault.setDepositorWhitelistStatus(OWNER_ADDRESS, true)
    ).resolves.not.toThrow();
  });

  test("redeem", async () => {
    await collateralContract.approve(VAULT_ADDRESS, DEFAULT_AMOUNT);
    await vault.deposit(OWNER_ADDRESS, DEFAULT_AMOUNT);

    const { withdrawnAssets, mintedShares } = await vault.redeem(
      OWNER_ADDRESS,
      DEFAULT_AMOUNT
    );

    expect(withdrawnAssets.toNumber()).toBeGreaterThan(0);
    expect(mintedShares.toNumber()).toBeGreaterThan(0);
  });
});
