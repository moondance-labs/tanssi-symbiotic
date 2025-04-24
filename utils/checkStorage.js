require("dotenv").config();

const { ethers } = require("ethers");
const { JsonRpcProvider } = ethers.providers;
const { hexValue } = ethers.utils;

const STAKER_CONTRACT = process.env.STAKER_CONTRACT;
const RPC_URL = process.env.RPC_URL;
const TOKEN_ADDRESS_TO_CHECK = process.env.TOKEN_ADDRESS_TO_CHECK;

let operatorAddresses = [];
if (process.env.OPERATOR_ADDRESSES) {
  operatorAddresses = process.env.OPERATOR_ADDRESSES.split(",").map((op) =>
    op.trim()
  );
} else if (process.env.OPERATOR_ADDRESS_TO_CHECK) {
  operatorAddresses = [process.env.OPERATOR_ADDRESS_TO_CHECK];
}

const PREVIOUS_STORAGE_LOCATION =
  "0xe07cde22a6017f26eee680b6867ce6727151fb6097c75742cbe379265c377400";
const NEW_STORAGE_LOCATION =
  "0xef473712465551821e7a51c85c06a1bf76bdf2a3508e28184170ac7eb0322c00";

// Read epoch from command line arguments
const epochArg = process.argv[2];

if (!STAKER_CONTRACT || !RPC_URL || !TOKEN_ADDRESS_TO_CHECK) {
  console.error("Error: Missing required environment variables in .env file.");
  console.error(
    "Please ensure CONTRACT_ADDRESS, RPC_URL, and TOKEN_ADDRESS_TO_CHECK are set."
  );
  process.exit(1);
}

if (!epochArg) {
  console.error("Error: Epoch number not provided as a command-line argument.");
  console.error("Usage: node checkStorage.js <epoch_number>");
  process.exit(1);
}

const EPOCH_TO_CHECK = parseInt(epochArg);
if (isNaN(EPOCH_TO_CHECK) || EPOCH_TO_CHECK < 0) {
  console.error(
    `Error: Invalid epoch number provided: "${epochArg}". Please provide a non-negative integer.`
  );
  process.exit(1);
}

/**
 * Function to get values from a specific storage slot
 *
 * @param {string} contractAddress - The address of the contract to read from
 * @param {array} data - The parameters to encode (array of strings)
 * @param {types} types - The types of the parameters (array of strings)
 * @param {string} locationSlot - The storage slot location (bytes32)
 * @param {ethers.providers.Provider} provider - The ethers provider
 * @returns {Promise<ethers.BigNumber>} The value stored at the calculated slot
 */
async function getLocationData(
  contractAddress,
  data,
  types,
  locationSlot,
  provider
) {
  const abiEncoder = new ethers.utils.AbiCoder();

  let mappingSlot = locationSlot;
  // Iterate through the data and types to calculate the final slot since for mapping each key needs to be hashed with the computed slot every time
  for (let i = 0; i < types.length; i++) {
    encoded = abiEncoder.encode([types[i], "bytes32"], [data[i], mappingSlot]);

    mappingSlot = ethers.utils.keccak256(encoded);
  }

  // Read the storage at the calculated slot
  const value = await provider.getStorageAt(contractAddress, mappingSlot);

  // Convert the bytes32 value to a BigNumber
  return ethers.BigNumber.from(value);
}

function getMappingStorageSlot(position, location) {
  return hexValue(
    ethers.BigNumber.from(location).add(position)
  );
}

async function checkOldStorageCleared() {
  const provider = new JsonRpcProvider(RPC_URL);
  console.log(
    `Checking OLD storage slots for Epoch ${EPOCH_TO_CHECK}, Token ${TOKEN_ADDRESS_TO_CHECK}`
  );
  console.log(`Contract: ${STAKER_CONTRACT}`);

  try {
    console.log(
      `\nPrevious Storage Base Slot (ERC-7201): ${PREVIOUS_STORAGE_LOCATION}`
    );
    console.log(
      `New Storage Base Slot (ERC-7201): ${NEW_STORAGE_LOCATION}`
    );

    // Determine the base slots for each mapping within the PreviousStakerRewardsStorage struct
    //   struct PreviousStakerRewardsStorage {
    //     uint256 adminFee; --- 0
    //     mapping(uint48 epoch => mapping(address tokenAddress => uint256[] rewards_)) rewards; --- 1
    //     mapping(address account => mapping(uint48 epoch => mapping(address tokenAddress => uint256 rewardIndex)))
    //         lastUnclaimedReward; --- 2
    //     mapping(uint48 epoch => mapping(address tokenAddress => uint256 amount)) claimableAdminFee; --- 3
    //     mapping(uint48 epoch => uint256 amount) activeSharesCache; --- 4
    //     mapping(uint48 epoch => bool) epochMigrated; --- 5
    // }

    const rewardsMappingBaseSlot = getMappingStorageSlot(1, PREVIOUS_STORAGE_LOCATION); // 1 is the mapping slot number for rewards
    const lastUnclaimedMappingBaseSlot = getMappingStorageSlot(2, PREVIOUS_STORAGE_LOCATION); // 2 is the mapping slot number for lastUnclaimedReward
    const claimableAdminFeeMappingBaseSlot = getMappingStorageSlot(3, PREVIOUS_STORAGE_LOCATION); // 3 is the mapping slot number for claimableAdminFee
    const activeSharesCacheMappingBaseSlot = getMappingStorageSlot(4, PREVIOUS_STORAGE_LOCATION); // 4 is the mapping slot number for activeSharesCache
    const epochMigratedMappingBaseSlot = getMappingStorageSlot(5, PREVIOUS_STORAGE_LOCATION); // 5 is the mapping slot number for epochMigrated

    const rewardsMappingBaseSlotNew = getMappingStorageSlot(1, NEW_STORAGE_LOCATION); // 1 is the mapping slot number for rewards
    const claimedRewardsMappingBaseSlotNew = getMappingStorageSlot(2, NEW_STORAGE_LOCATION); // 2 is the mapping slot number for claimedRewards

    // $$.rewards[epoch][tokenAddress]
    try {
      const dataForRewards = [EPOCH_TO_CHECK, TOKEN_ADDRESS_TO_CHECK];
      const typesForRewards = ["uint48", "address"];
      const value = await getLocationData(
        STAKER_CONTRACT,
        dataForRewards,
        typesForRewards,
        rewardsMappingBaseSlot,
        provider
      );
      console.log("Old Storage value for rewards length:", value.toString());
    } catch (error) {
      console.error("Error reading storage for rewards length:", error);
      throw error;
    }

    // $$.activeSharesCache[epoch]
    try {
      const dataForActiveSharesCache = [EPOCH_TO_CHECK];
      const typesForActiveSharesCache = ["uint48"];
      const value = await getLocationData(
        STAKER_CONTRACT,
        dataForActiveSharesCache,
        typesForActiveSharesCache,
        activeSharesCacheMappingBaseSlot,
        provider
      );
      console.log("Old Storage value for activeSharesCache:", value.toString());
    } catch (error) {
      console.error("Error reading storage for activeSharesCache:", error);
      throw error;
    }

    // $$.claimableAdminFee[epoch][tokenAddress]
    try {
      const dataForClaimableAdminFee = [EPOCH_TO_CHECK, TOKEN_ADDRESS_TO_CHECK];
      const typesForClaimableAdminFee = ["uint48", "address"];
      const value = await getLocationData(
        STAKER_CONTRACT,
        dataForClaimableAdminFee,
        typesForClaimableAdminFee,
        claimableAdminFeeMappingBaseSlot,
        provider
      );
      console.log("Old Storage value for claimableAdminFee:", value.toString());
    } catch (error) {
      console.error("Error reading storage for claimableAdminFee:", error);
      throw error;
    }

    // $$.lastUnclaimedReward[account][epoch][tokenAddress]
    if (operatorAddresses.length > 0) {
      for (const operator of operatorAddresses) {
        try {
          const dataForLastUnclaimedReward = [
            operator,
            EPOCH_TO_CHECK,
            TOKEN_ADDRESS_TO_CHECK,
          ];
          const typesForLastUnclaimedReward = ["address", "uint48", "address"];

          const value = await getLocationData(
            STAKER_CONTRACT,
            dataForLastUnclaimedReward,
            typesForLastUnclaimedReward,
            lastUnclaimedMappingBaseSlot,
            provider
          );
          console.log(
            `Old Storage value for lastUnclaimedReward for operator ${operator}:`,
            value.toString()
          );
        } catch (error) {
          console.error(
            `Error reading storage for lastUnclaimedReward for operator ${operator}:`,
            error
          );
          throw error;
        }
      }
    }

    // $$.epochMigrated[epoch]
    try {
      const dataForEpochMigrated = [EPOCH_TO_CHECK];
      const typesForEpochMigrated = ["uint48"];
      const value = await getLocationData(
        STAKER_CONTRACT,
        dataForEpochMigrated,
        typesForEpochMigrated,
        epochMigratedMappingBaseSlot,
        provider
      );
      console.log("Old Storage value for epochMigrated:", value.toString());
    } catch (error) {
      console.error("Error reading storage for epochMigrated:", error);
      throw error;
    }

  // $.rewards[epoch][tokenAddress]
    try {
      const dataForRewards = [EPOCH_TO_CHECK, TOKEN_ADDRESS_TO_CHECK];
      const typesForRewards = ["uint48", "address"];
      const value = await getLocationData(
        STAKER_CONTRACT,
        dataForRewards,
        typesForRewards,
        rewardsMappingBaseSlotNew,
        provider
      );
      console.log("New Storage value for rewards:", value.toString());
    } catch (error) {
      console.error("Error reading storage for new rewards:", error);
      throw error;
    }

    // $.stakerClaimedRewardPerEpoch[account][epoch][tokenAddress]
    if (operatorAddresses.length > 0) {
      for (const operator of operatorAddresses) {
        try {
          const dataForStakerClaimedRewardPerEpoch = [operator, EPOCH_TO_CHECK, TOKEN_ADDRESS_TO_CHECK];
          const typesForStakerClaimedRewardPerEpoch = ["address", "uint48", "address"];
          const value = await getLocationData(
            STAKER_CONTRACT,
            dataForStakerClaimedRewardPerEpoch,
            typesForStakerClaimedRewardPerEpoch,
            claimedRewardsMappingBaseSlotNew,
            provider
          );
          console.log(`New Storage value Claimed rewards for operator ${operator}:`, value.toString());
        } catch (error) {
          console.error("Error reading storage for claimed rewards:", error);
          throw error;
        }
      }
    }
    
  } catch (error) {
    console.error("\n--- ERROR ---");

    console.error("An unexpected error occurred:", error.message || error);
    process.exit(1);
  }
}

checkOldStorageCleared();
