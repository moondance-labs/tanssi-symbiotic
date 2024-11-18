import { ethers } from "ethers";
import { OPT_IN_ABI } from "./opt_in_abi";
import { validateAddress } from "../utils";

/**
 * @notice API for interacting with a Vault contract
 */
export class OptInAPI {
  private contract: ethers.Contract;

  constructor(optInAddress: string, wallet: ethers.Wallet) {
    validateAddress(optInAddress);
    this.contract = new ethers.Contract(optInAddress, OPT_IN_ABI, wallet);
  }

  /**
   * @notice Get if a given "who" is opted-in to a particular "where" entity at a given timestamp using a hint.
   * @param who address of the "who"
   * @param where address of the "where" entity
   * @param timestamp time point to get if the "who" is opted-in at
   * @param hint hint for the checkpoint index
   * @return if the "who" is opted-in at the given timestamp
   */
  async isOptedInAt(
    who: string,
    where: string,
    timestamp: number,
    hint: string
  ): Promise<boolean> {
    try {
      const result = await this.contract.isOptedInAt(
        who,
        where,
        timestamp,
        hint
      );
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get if ${who} is opted-in at ${timestamp} to ${where}: ${error.message}`,
        error.code
      );
    }
  }
  //   function isOptedInAt(
  //     address who,
  //     address where,
  //     uint48 timestamp,
  //     bytes calldata hint
  // ) external view returns (bool);

  /**
   * @notice Check if a given "who" is opted-in to a particular "where" entity.
   * @param who address of the "who"
   * @param where address of the "where" entity
   * @return if the "who" is opted-in
   */
  // function isOptedIn(address who, address where) external view returns (bool);
  async isOptedIn(who: string, where: string): Promise<boolean> {
    try {
      const result = await this.contract.isOptedIn(who, where);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get if ${who} is opted-in to ${where}: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Get the nonce of a given "who" to a particular "where" entity.
   * @param who address of the "who"
   * @param where address of the "where" entity
   * @return nonce
   */

  async nonces(who: string, where: string): Promise<ethers.BigNumber> {
    try {
      const result = await this.contract.nonces(who, where);
      return result;
    } catch (error) {
      throw new Error(
        `Failed to get nonce of ${who} to ${where}: ${error.message}`,
        error.code
      );
    }
  }

  /**
   * @notice Opt-in a calling "who" to a particular "where" entity.
   * @param where address of the "where" entity
   */
  async optIn(where: string): Promise<void>;
  /**
   * @notice Opt-in a "who" to a particular "where" entity with a signature.
   * @param who address of the "who"
   * @param where address of the "where" entity
   * @param deadline time point until the signature is valid (inclusively)
   * @param signature signature of the "who"
   */
  async optIn(
    who: string,
    where: string,
    deadline: number,
    signature: string
  ): Promise<void>;

  async optIn(
    whoOrWhere: string,
    where?: string,
    deadline?: number,
    signature?: string
  ): Promise<void> {
    try {
      let tx: ethers.ContractTransaction;

      if (where === undefined) {
        tx = await this.contract["optIn(address)"](whoOrWhere);
      } else {
        tx = await this.contract["optIn(address,address,uint48,bytes)"](
          whoOrWhere,
          where,
          deadline!,
          signature!
        );
      }

      await tx.wait();
    } catch (error) {
      const errorMessage =
        where === undefined
          ? `Failed to opt-in from ${whoOrWhere}: ${error.message}`
          : `Failed to opt-in ${whoOrWhere} from ${where}: ${error.message}`;

      throw new Error(errorMessage, { cause: error });
    }
  }

  /**
   * @notice Opt-out a calling "who" from a particular "where" entity.
   * @param where address of the "where" entity
   */
  async optOut(where: string): Promise<void>;

  /**
   * @notice Opt-out a "who" from a particular "where" entity with a signature.
   * @param who address of the "who"
   * @param where address of the "where" entity
   * @param deadline time point until the signature is valid (inclusively)
   * @param signature signature of the "who"
   */
  async optOut(
    who: string,
    where: string,
    deadline: number,
    signature: string
  ): Promise<void>;

  async optOut(
    whoOrWhere: string,
    where?: string,
    deadline?: number,
    signature?: string
  ): Promise<void> {
    try {
      let tx: ethers.ContractTransaction;

      if (where === undefined) {
        tx = await this.contract["optOut(address)"](whoOrWhere);
      } else {
        tx = await this.contract["optOut(address,address,uint48,bytes)"](
          whoOrWhere,
          where,
          deadline!,
          signature!
        );
      }

      await tx.wait();
    } catch (error) {
      const errorMessage =
        where === undefined
          ? `Failed to opt-out from ${whoOrWhere}: ${error.message}`
          : `Failed to opt-out ${whoOrWhere} from ${where}: ${error.message}`;

      throw new Error(errorMessage, { cause: error });
    }
  }

  /**
   * @notice Increase the nonce of a given "who" to a particular "where" entity.
   * @param where address of the "where" entity
   * @dev It can be used to invalidate a given signature.
   */
  async increaseNonce(where: string): Promise<void> {
    try {
      const tx = await this.contract.increaseNonce(where);
      await tx.wait();
    } catch (error) {
      throw new Error(
        `Failed to increase nonce to ${where}: ${error.message}`,
        error.code
      );
    }
  }
}
