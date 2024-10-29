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
  async getSlasher(): Promise<string> {
    try {
      return await this.contract.slasher();
    } catch (error) {
      throw new Error(`Failed to retrieve slasher: ${error.message}`);
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
