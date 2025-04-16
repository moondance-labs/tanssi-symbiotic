import { ethers } from "ethers";

export function decodeOperatorsData(payload: string): {
  operatorsKeys: string[];
  operatorsCount: number;
  epoch: number;
} {
  // Convert to bytes array if it's a hex string
  const bytes = ethers.utils.arrayify(payload);

  // Extract parts based on the encoding pattern:
  // [0-3]: bytes4(0x70150038) - Magic bytes/selector
  // [4]: bytes1(uint8(Message.V0)) - Message version
  // [5]: bytes1(uint8(OutboundCommandV1.ReceiveValidators)) - Command type
  // [6-?]: ScaleCodec.encodeCompactU32(operatorsCount) - Operators count (variable length)
  // [?-(n*32)]: operatorsFlattened - The keys as flattened bytes
  // [last 8 bytes]: ScaleCodec.encodeU64(uint64(epoch)) - Epoch

  // First verify the magic bytes
  const magicBytes = bytes.slice(0, 4);
  const expectedMagic = [0x70, 0x15, 0x00, 0x38];
  if (!magicBytes.every((b, i) => b === expectedMagic[i])) {
    throw new Error("Invalid magic bytes in payload");
  }

  // Skip version and command (1 byte each)
  let offset = 6;

  // Decode the SCALE-encoded operators count
  // Basic SCALE compact decoding for uint
  let operatorsCount = 0;
  const firstByte = bytes[offset];

  if ((firstByte & 0b11) === 0b00) {
    // Single-byte mode
    operatorsCount = firstByte >> 2;
    offset += 1;
  } else if ((firstByte & 0b11) === 0b01) {
    // Two-byte mode
    operatorsCount = ((bytes[offset + 1] << 6) | (firstByte >> 2)) & 0x3fff;
    offset += 2;
  } else if ((firstByte & 0b11) === 0b10) {
    // Four-byte mode
    operatorsCount =
      ((bytes[offset + 3] << 22) |
        (bytes[offset + 2] << 14) |
        (bytes[offset + 1] << 6) |
        (firstByte >> 2)) &
      0x3fffffff;
    offset += 4;
  } else {
    throw new Error("Operators count too large");
  }

  // Extract flattened operators keys
  const operatorsFlattened = bytes.slice(offset, offset + operatorsCount * 32);
  offset += operatorsCount * 32;

  // Last 8 bytes are the epoch
  const epochBytes = bytes.slice(bytes.length - 8);

  // SCALE codec uses little-endian, so we need to reverse the bytes for ethers.js which expects big-endian
  const reversedEpochBytes = new Uint8Array(epochBytes).reverse();

  const epochHex = ethers.utils.hexlify(reversedEpochBytes);

  const epochValue = ethers.BigNumber.from(epochHex).toNumber();

  // Convert flattened operators back to bytes32 array
  const operatorsKeys: string[] = [];
  for (let i = 0; i < operatorsCount; i++) {
    const key = ethers.utils.hexlify(
      operatorsFlattened.slice(i * 32, (i + 1) * 32)
    );
    operatorsKeys.push(key);
  }

  return {
    operatorsKeys,
    operatorsCount,
    epoch: epochValue,
  };
}
