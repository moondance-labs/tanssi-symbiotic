import { ethers } from "ethers";
import { VAULT_ABI } from "./vault_abi";
import { validateAddress } from "../utils";

/**
 * @notice API for interacting with a Vault contract
 */
export class VaultAPI {
  private contract: ethers.Contract;

  constructor(vaultAddress: string, wallet: ethers.Wallet) {
    validateAddress(vaultAddress);
    this.contract = new ethers.Contract(vaultAddress, VAULT_ABI, wallet);
  }

  // View Functions
  /**
   * @notice Get the vault owner
   * @return The address of the vault owner
   */
  async owner(): Promise<string> {
    try {
      return await this.contract.owner();
    } catch (error) {
      throw new Error(`Failed to retrieve owner: ${error.message}`);
    }
  }

  /**
   * @notice Get the slasher associated with the vault
   * @return The address of the slasher contract
   */
  async slasher(): Promise<string> {
    try {
      return await this.contract.slasher();
    } catch (error) {
      throw new Error(`Failed to retrieve slasher: ${error.message}`);
    }
  }

  /**
   * @notice Get a vault collateral.
   * @return address of the underlying collateral
   */
  async collateral(): Promise<string> {
    try {
      return await this.contract.collateral();
    } catch (error) {
      throw new Error(`Failed to retrieve collateral: ${error.message}`);
    }
  }

  /**
   * @notice Get a burner to issue debt to (e.g., 0xdEaD or some unwrapper contract).
   * @return address of the burner
   */
  async burner(): Promise<string> {
    try {
      return await this.contract.burner();
    } catch (error) {
      throw new Error(`Failed to retrieve burner: ${error.message}`);
    }
  }

  /**
   * @notice Get a delegator (it delegates the vault's stake to networks and operators).
   * @return address of the delegator
   */
  async delegator(): Promise<string> {
    try {
      return await this.contract.delegator();
    } catch (error) {
      throw new Error(`Failed to retrieve delegator: ${error.message}`);
    }
  }

  /**
   * @notice Get if the delegator is initialized.
   * @return if the delegator is initialized
   */
  async isDelegatorInitialized(): Promise<boolean> {
    try {
      return await this.contract.isDelegatorInitialized();
    } catch (error) {
      throw new Error(
        `Failed to check if delegator is initialized: ${error.message}`
      );
    }
  }

  /**
   * @notice Get if the slasher is initialized.
   * @return if the slasher is initialized
   */
  async isSlasherInitialized(): Promise<boolean> {
    try {
      return await this.contract.isSlasherInitialized();
    } catch (error) {
      throw new Error(
        `Failed to check if slasher is initialized: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a time point of the epoch duration set.
   * @return time point of the epoch duration set
   */
  async epochDurationInit(): Promise<number> {
    try {
      return await this.contract.epochDurationInit();
    } catch (error) {
      throw new Error(
        `Failed to retrieve epoch duration init: ${error.message}`
      );
    }
  }
  /**
   * @notice Get a duration of the vault epoch.
   * @return duration of the epoch
   */
  async epochDuration(): Promise<number> {
    try {
      return await this.contract.epochDuration();
    } catch (error) {
      throw new Error(`Failed to retrieve epoch duration: ${error.message}`);
    }
  }

  /**
   * @notice Get an epoch at a given timestamp.
   * @param timestamp time point to get the epoch at
   * @return epoch at the timestamp
   * @dev Reverts if the timestamp is less than the start of the epoch 0.
   */
  async epochAt(timestamp: number): Promise<number> {
    try {
      return await this.contract.epochAt(timestamp);
    } catch (error) {
      throw new Error(`Failed to get epoch at ${timestamp}: ${error.message}`);
    }
  }

  /**
   * @notice Get a current vault epoch.
   * @return current epoch
   */
  async currentEpoch(): Promise<number> {
    try {
      return await this.contract.currentEpoch();
    } catch (error) {
      throw new Error(`Failed to get current epoch: ${error.message}`);
    }
  }

  /**
   * @notice Get a start of the current vault epoch.
   * @return start of the current epoch
   */
  async currentEpochStart(): Promise<number> {
    try {
      return await this.contract.currentEpochStart();
    } catch (error) {
      throw new Error(`Failed to get current epoch start: ${error.message}`);
    }
  }

  /**
   * @notice Get a start of the previous vault epoch.
   * @return start of the previous epoch
   * @dev Reverts if the current epoch is 0.
   */
  async previousEpochStart(): Promise<number> {
    try {
      return await this.contract.previousEpochStart();
    } catch (error) {
      throw new Error(`Failed to get previous epoch start: ${error.message}`);
    }
  }

  /**
   * @notice Get a start of the next vault epoch.
   * @return start of the next epoch
   */
  async nextEpochStart(): Promise<number> {
    try {
      return await this.contract.nextEpochStart();
    } catch (error) {
      throw new Error(`Failed to get next epoch start: ${error.message}`);
    }
  }

  /**
   * @notice Get if the deposit whitelist is enabled.
   * @return if the deposit whitelist is enabled
   */
  async depositWhitelist(): Promise<boolean> {
    try {
      return await this.contract.depositWhitelist();
    } catch (error) {
      throw new Error(
        `Failed to get deposit whitelist status: ${error.message}`
      );
    }
  }

  /**
   * @notice Get if a given account is whitelisted as a depositor.
   * @param account address to check
   * @return if the account is whitelisted as a depositor
   */
  async isDepositorWhitelisted(account: string): Promise<boolean> {
    validateAddress(account);
    try {
      return await this.contract.isDepositorWhitelisted(account);
    } catch (error) {
      throw new Error(
        `Failed to check if ${account} is a whitelisted depositor: ${error.message}`
      );
    }
  }
  /**
   * @notice Get if the deposit limit is set.
   * @return if the deposit limit is set
   */
  async isDepositLimit(): Promise<boolean> {
    try {
      return await this.contract.isDepositLimit();
    } catch (error) {
      throw new Error(`Failed to get deposit limit status: ${error.message}`);
    }
  }

  /**
   * @notice Get a deposit limit (maximum amount of the active stake that can be in the vault simultaneously).
   * @return deposit limit
   */
  async depositLimit(): Promise<number> {
    try {
      return await this.contract.depositLimit();
    } catch (error) {
      throw new Error(`Failed to get deposit limit: ${error.message}`);
    }
  }

  /**
   * @notice Get a total number of active shares in the vault at a given timestamp using a hint.
   * @param timestamp time point to get the total number of active shares at
   * @param hint hint for the checkpoint index
   * @return total number of active shares at the timestamp
   */
  async activeSharesAt(timestamp: number, hint: string): Promise<number> {
    try {
      return await this.contract.activeSharesAt(timestamp, hint);
    } catch (error) {
      throw new Error(
        `Failed to get active shares at ${timestamp}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a total number of active shares in the vault.
   * @return total number of active shares
   */
  async activeShares(): Promise<number> {
    try {
      return await this.contract.activeShares();
    } catch (error) {
      throw new Error(`Failed to get active shares: ${error.message}`);
    }
  }

  /**
   * @notice Get a total amount of active stake in the vault at a given timestamp using a hint.
   * @param timestamp time point to get the total active stake at
   * @param hint hint for the checkpoint index
   * @return total amount of active stake at the timestamp
   */
  async activeStakeAt(timestamp: number, hint: string): Promise<number> {
    try {
      return await this.contract.activeStakeAt(timestamp, hint);
    } catch (error) {
      throw new Error(
        `Failed to get active stake at ${timestamp}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a total amount of active stake in the vault.
   * @return total amount of active stake
   */
  async activeStake(): Promise<number> {
    try {
      return await this.contract.activeStake();
    } catch (error) {
      throw new Error(`Failed to get active stake: ${error.message}`);
    }
  }
  /**
   * @notice Get a total number of active shares for a particular account at a given timestamp using a hint.
   * @param account account to get the number of active shares for
   * @param timestamp time point to get the number of active shares for the account at
   * @param hint hint for the checkpoint index
   * @return number of active shares for the account at the timestamp
   */
  async activeSharesOfAt(
    account: string,
    timestamp: number,
    hint: string
  ): Promise<number> {
    validateAddress(account);
    try {
      return await this.contract.activeSharesOfAt(account, timestamp, hint);
    } catch (error) {
      throw new Error(
        `Failed to get active shares for ${account} at ${timestamp}: ${error.message}`
      );
    }
  }
  /**
   * @notice Get a number of active shares for a particular account.
   * @param account account to get the number of active shares for
   * @return number of active shares for the account
   */
  async activeSharesOf(account: string): Promise<number> {
    validateAddress(account);
    try {
      return await this.contract.activeSharesOf(account);
    } catch (error) {
      throw new Error(
        `Failed to get active shares for ${account}: ${error.message}`
      );
    }
  }
  /**
   * @notice Get a total amount of the withdrawals at a given epoch.
   * @param epoch epoch to get the total amount of the withdrawals at
   * @return total amount of the withdrawals at the epoch
   */
  async withdrawals(epoch: number): Promise<number> {
    try {
      return await this.contract.withdrawals(epoch);
    } catch (error) {
      throw new Error(
        `Failed to get withdrawals at epoch ${epoch}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get a total number of withdrawal shares at a given epoch.
   * @param epoch epoch to get the total number of withdrawal shares at
   * @return total number of withdrawal shares at the epoch
   */
  async withdrawalShares(epoch: number): Promise<number> {
    try {
      return await this.contract.withdrawalShares(epoch);
    } catch (error) {
      throw new Error(
        `Failed to get withdrawal shares at epoch ${epoch}: ${error.message}`
      );
    }
  }
  /**
   * @notice Get a number of withdrawal shares for a particular account at a given epoch (zero if claimed).
   * @param epoch epoch to get the number of withdrawal shares for the account at
   * @param account account to get the number of withdrawal shares for
   * @return number of withdrawal shares for the account at the epoch
   */
  async withdrawalSharesOf(epoch: number, account: string): Promise<number> {
    validateAddress(account);
    try {
      return await this.contract.withdrawalSharesOf(epoch, account);
    } catch (error) {
      throw new Error(
        `Failed to get withdrawal shares for ${account} at epoch ${epoch}: ${error.message}`
      );
    }
  }
  /**
   * @notice Get if the withdrawals are claimed for a particular account at a given epoch.
   * @param epoch epoch to check the withdrawals for the account at
   * @param account account to check the withdrawals for
   * @return if the withdrawals are claimed for the account at the epoch
   */
  async isWithdrawalsClaimed(epoch: number, account: string): Promise<boolean> {
    validateAddress(account);
    try {
      return await this.contract.isWithdrawalsClaimed(epoch, account);
    } catch (error) {
      throw new Error(
        `Failed to check if withdrawals are claimed for ${account} at epoch ${epoch}: ${error.message}`
      );
    }
  }
  /**
   * @notice Check if the vault is initialized
   * @return True if the vault is initialized, false otherwise
   */
  async isInitialized(): Promise<boolean> {
    try {
      return await this.contract.isInitialized();
    } catch (error) {
      throw new Error(
        `Failed to check initialization status: ${error.message}`
      );
    }
  }

  /**
   * @notice Get the total stake in the vault
   * @return Total stake in the vault
   */
  async totalStake(): Promise<ethers.BigNumber> {
    try {
      return await this.contract.totalStake();
    } catch (error) {
      throw new Error(`Failed to retrieve total stake: ${error.message}`);
    }
  }

  /**
   * @notice Get the active balance of an account
   * @param account Account address
   */
  async activeBalanceOf(account: string): Promise<ethers.BigNumber> {
    validateAddress(account);
    try {
      return await this.contract.activeBalanceOf(account);
    } catch (error) {
      throw new Error(
        `Failed to get active balance for ${account}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get the active balance of an account at a specific timestamp
   * @param account Account address
   * @param timestamp Timestamp at which to check the balance
   * @param hints Hints for the checkpoints' indexes
   * @return Active balance at the specified timestamp
   */
  async activeBalanceOfAt(
    account: string,
    timestamp: number,
    hints: string = "0x"
  ): Promise<ethers.BigNumber> {
    validateAddress(account);
    try {
      return await this.contract.activeBalanceOfAt(account, timestamp, hints);
    } catch (error) {
      throw new Error(
        `Failed to get active balance at ${timestamp}: ${error.message}`
      );
    }
  }

  /**
   * @notice Get the slashable balance of an account
   * @param account Account address
   * @return Slashable balance of the account
   */
  async slashableBalanceOf(account: string): Promise<ethers.BigNumber> {
    validateAddress(account);
    try {
      return await this.contract.slashableBalanceOf(account);
    } catch (error) {
      throw new Error(
        `Failed to get slashable balance for ${account}: ${error.message}`
      );
    }
  }

  /**
   * @notice Deposit amount on behalf of an account
   * @params onBehalfOf Account address
   * @params amount Amount to deposit
   * @return depositedAmount real amount of the collateral deposited
   * @return mintedShares amount of the active shares minted
   */
  async deposit(
    onBehalfOf: string,
    amount: ethers.BigNumber
  ): Promise<{
    depositedAmount: ethers.BigNumber;
    mintedShares: ethers.BigNumber;
  }> {
    validateAddress(onBehalfOf);
    try {
      const tx = await this.contract.deposit(onBehalfOf, amount);

      const receipt = await tx.wait();

      const { depositedAmount, mintedShares } =
        this.contract.interface.decodeFunctionResult(
          "deposit",
          receipt.logs[receipt.logs.length - 1].data
        );

      return {
        depositedAmount,
        mintedShares,
      };
    } catch (error) {
      throw new Error(`Failed to deposit for ${onBehalfOf}: ${error.message}`);
    }
  }

  /**
   * @notice Withdraw an amount for an account
   * @param claimer Account address
   * @param amount Amount to withdraw
   * @return burnedShares amount of the active shares burned
   * @return mintedShares amount of the epoch withdrawal shares minted
   */
  async withdraw(
    claimer: string,
    amount: ethers.BigNumber
  ): Promise<{
    burnedShares: ethers.BigNumber;
    mintedShares: ethers.BigNumber;
  }> {
    validateAddress(claimer);
    try {
      const tx = await this.contract.withdraw(claimer, amount);

      const receipt = await tx.wait();

      const { burnedShares, mintedShares } =
        this.contract.interface.decodeFunctionResult(
          "withdraw",
          receipt.logs[receipt.logs.length - 1].data
        );

      return {
        burnedShares,
        mintedShares,
      };
    } catch (error) {
      throw new Error(`Failed to withdraw for ${claimer}: ${error.message}`);
    }
  }

  /**
   * @notice Redeem collateral from the vault (it will be claimable after the next epoch).
   * @param claimer account that needs to claim the withdrawal
   * @param shares amount of the active shares to redeem
   * @return withdrawnAssets amount of the collateral withdrawn
   * @return mintedShares amount of the epoch withdrawal shares minted
   */
  async redeem(
    claimer: string,
    shares: ethers.BigNumber
  ): Promise<{
    withdrawnAssets: ethers.BigNumber;
    mintedShares: ethers.BigNumber;
  }> {
    validateAddress(claimer);
    try {
      const tx = await this.contract.redeem(claimer, shares);
      const receipt = await tx.wait();

      const { withdrawnAssets, mintedShares } =
        this.contract.interface.decodeFunctionResult(
          "redeem",
          receipt.logs[receipt.logs.length - 1].data
        );
      return {
        withdrawnAssets,
        mintedShares,
      };
    } catch (error) {
      throw new Error(`Failed to redeem for ${claimer}: ${error.message}`);
    }
  }

  /**
   * @notice Claim collateral from the vault.
   * @param recipient account that receives the collateral
   * @param epoch epoch to claim the collateral for
   * @return amount amount of the collateral claimed
   */
  async claim(recipient: string, epoch: number): Promise<ethers.BigNumber> {
    validateAddress(recipient);
    try {
      const tx = await this.contract.claim(recipient, epoch);
      const receipt = await tx.wait();

      const { amount } = this.contract.interface.decodeFunctionResult(
        "claim",
        receipt.logs[receipt.logs.length - 1].data
      );
      return amount;
    } catch (error) {
      throw new Error(
        `Failed to claim for ${recipient} at epoch ${epoch}: ${error.message}`
      );
    }
  }

  /**
   * @notice Claim collateral from the vault for multiple epochs.
   * @param recipient account that receives the collateral
   * @param epochs epochs to claim the collateral for
   * @return amount amount of the collateral claimed
   */
  async claimBatch(
    recipient: string,
    epochs: number[]
  ): Promise<ethers.BigNumber> {
    validateAddress(recipient);
    try {
      const tx = await this.contract.claimBatch(recipient, epochs);
      const receipt = await tx.wait();

      const { amount } = this.contract.interface.decodeFunctionResult(
        "claimBatch",
        receipt.logs[receipt.logs.length - 1].data
      );
      return amount;
    } catch (error) {
      throw new Error(
        `Failed to claim batch for ${recipient}: ${error.message}`
      );
    }
  }

  /**
   * @notice Slash callback for burning collateral.
   * @param amount amount to slash
   * @param captureTimestamp time point when the stake was captured
   * @return slashedAmount real amount of the collateral slashed
   * @dev Only the slasher can call this function.
   */
  async onSlash(
    amount: ethers.BigNumber,
    captureTimestamp: number
  ): Promise<ethers.BigNumber> {
    try {
      const tx = await this.contract.onSlash(amount, captureTimestamp);
      const receipt = await tx.wait();

      const { slashedAmount } = this.contract.interface.decodeFunctionResult(
        "onSlash",
        receipt.logs[receipt.logs.length - 1].data
      );
      return slashedAmount;
    } catch (error) {
      throw new Error(`Failed to slash: ${error.message}`);
    }
  }

  /**
   * @notice Enable/disable deposit whitelist.
   * @param status if enabling deposit whitelist
   * @dev Only a DEPOSIT_WHITELIST_SET_ROLE holder can call this function.
   */
  async setDepositWhitelist(status: boolean): Promise<void> {
    try {
      const tx = await this.contract.setDepositWhitelist(status);
      await tx.wait();
    } catch (error) {
      throw new Error(
        `Failed to set deposit whitelist status: ${error.message}`
      );
    }
  }

  /**
   * @notice Set a depositor whitelist status.
   * @param account account for which the whitelist status is set
   * @param status if whitelisting the account
   * @dev Only a DEPOSITOR_WHITELIST_ROLE holder can call this function.
   */

  async setDepositorWhitelistStatus(
    account: string,
    status: boolean
  ): Promise<void> {
    validateAddress(account);
    try {
      const tx = await this.contract.setDepositorWhitelistStatus(
        account,
        status
      );
      await tx.wait();
    } catch (error) {
      throw new Error(
        `Failed to set whitelist status for ${account}: ${error.message}`
      );
    }
  }

  /**
   * @notice Enable/disable deposit limit.
   * @param status if enabling deposit limit
   * @dev Only a IS_DEPOSIT_LIMIT_SET_ROLE holder can call this function.
   */
  async setIsDepositLimit(status: boolean): Promise<void> {
    try {
      const tx = await this.contract.setIsDepositLimit(status);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to set deposit limit status: ${error.message}`);
    }
  }

  /**
   * @notice Set a deposit limit.
   * @param limit deposit limit (maximum amount of the collateral that can be in the vault simultaneously)
   * @dev Only a DEPOSIT_LIMIT_SET_ROLE holder can call this function.
   */
  async setDepositLimit(limit: number): Promise<void> {
    try {
      const tx = await this.contract.setDepositLimit(limit);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to set deposit limit: ${error.message}`);
    }
  }

  /**
   * @notice Set a delegator.
   * @param delegator vault's delegator to delegate the stake to networks and operators
   * @dev Can be set only once.
   */

  async setDelegator(delegatorAddress: string): Promise<void> {
    validateAddress(delegatorAddress);
    try {
      const tx = await this.contract.setDelegator(delegatorAddress);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to set delegator: ${error.message}`);
    }
  }

  /**
   * @notice Set a slasher.
   * @param slasher vault's slasher to provide a slashing mechanism to networks
   * @dev Can be set only once.
   */
  async setSlasher(slasherAddress: string): Promise<void> {
    validateAddress(slasherAddress);
    try {
      const tx = await this.contract.setSlasher(slasherAddress);
      await tx.wait();
    } catch (error) {
      throw new Error(`Failed to set slasher: ${error.message}`);
    }
  }
}
