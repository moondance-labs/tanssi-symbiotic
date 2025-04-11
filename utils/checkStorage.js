require("dotenv").config();

const { ethers } = require("ethers");
const { JsonRpcProvider } = ethers.providers;
const { hexValue } = ethers.utils;

const STAKER_CONTRACT = process.env.STAKER_CONTRACT;
const RPC_URL = process.env.RPC_URL;
const TOKEN_ADDRESS_TO_CHECK = process.env.TOKEN_ADDRESS_TO_CHECK;
const OPERATOR_ADDRESS_TO_CHECK = process.env.OPERATOR_ADDRESS_TO_CHECK;
const PREVIOUS_STORAGE_LOCATION =
  "0xe07cde22a6017f26eee680b6867ce6727151fb6097c75742cbe379265c377400";

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

const EPOCH_TO_CHECK = parseInt(epochArg, 10);
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

    // Determine the base slots for each mapping within the PreviousStakerRewardsStorage struct
    const rewardsMappingBaseSlot = hexValue(
      ethers.BigNumber.from(PREVIOUS_STORAGE_LOCATION).add(1) // 1 is the mapping slot number for rewards
    );
    const lastUnclaimedMappingBaseSlot = hexValue(
      ethers.BigNumber.from(PREVIOUS_STORAGE_LOCATION).add(2) // 2 is the mapping slot number for lastUnclaimedRewardsIndex
    );
    const claimableAdminFeeMappingBaseSlot = hexValue(
      ethers.BigNumber.from(PREVIOUS_STORAGE_LOCATION).add(3) // 3 is the mapping slot number for claimableAdminFee
    );
    const activeSharesCacheMappingBaseSlot = hexValue(
      ethers.BigNumber.from(PREVIOUS_STORAGE_LOCATION).add(4) // 4 is the mapping slot number for activeSharesCache
    );

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
      console.log("Storage value for rewards length:", value.toString());
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
      console.log("Storage value for activeSharesCache:", value.toString());
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
      console.log("Storage value for claimableAdminFee:", value.toString());
    } catch (error) {
      console.error("Error reading storage for claimableAdminFee:", error);
      throw error;
    }

    // $$.lastUnclaimedReward[account][epoch][tokenAddress]
    if (OPERATOR_ADDRESS_TO_CHECK) {
      try {
        const dataForLastUnclaimedReward = [
          OPERATOR_ADDRESS_TO_CHECK,
          EPOCH_TO_CHECK,
          TOKEN_ADDRESS_TO_CHECK,
        ];
        const typesForLastUnclaimedReward = ["address", "uint48", "address"];
        const value = await getLocationData(
          STAKER_CONTRACT,
          dataForLastUnclaimedReward,
          typesForLastUnclaimedReward,
          claimableAdminFeeMappingBaseSlot,
          provider
        );
        console.log("Storage value for lastUnclaimedReward:", value.toString());
      } catch (error) {
        console.error("Error reading storage for lastUnclaimedReward:", error);
        throw error;
      }
    }
  } catch (error) {
    console.error("\n--- ERROR ---");

    console.error("An unexpected error occurred:", error.message || error);
    process.exit(1);
  }
}

checkOldStorageCleared();
