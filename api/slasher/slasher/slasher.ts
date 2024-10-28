import { ethers } from "ethers";
import { SLASHER_ABI } from "./slasher_abi";
import { BaseSlasherAPI, SlashParams } from "../base_slasher/base_slasher";

export class SlasherAPI extends BaseSlasherAPI {
  constructor(slasherAddress: string, wallet: ethers.Wallet) {
    super(slasherAddress, wallet);
    this.contract = new ethers.Contract(slasherAddress, SLASHER_ABI, wallet);
  }

  /**
   * @notice Perform a slash using a subnetwork for a particular operator by a given amount using hints.
   * @param subnetwork full identifier of the subnetwork (address of the network concatenated with the uint96 identifier)
   * @param operator address of the operator
   * @param amount maximum amount of the collateral to be slashed
   * @param captureTimestamp time point when the stake was captured
   * @param hints hints for checkpoints' indexes
   * @returns Promise resolving to slashed amount
   */
  async slash({
    subnetwork,
    operator,
    amount,
    captureTimestamp,
    hints,
  }: Required<SlashParams>): Promise<ethers.BigNumber> {
    try {
      const tx = await this.contract.slash(
        subnetwork,
        operator,
        amount,
        captureTimestamp,
        hints
      );

      return tx.slashedAmount;
    } catch (error) {
      throw new Error(`Slash operation failed: ${error.message}`, error.code);
    }
  }
}
