const defaultStart = 0;
const encodedByteLengths = {253: 3, 254: 5, 255: 9};
const minimumNumbers = {3: BigInt(253), 5: BigInt(65536), 9: BigInt(2 ** 32)};
const shiftByte = BigInt(8);
const singleByteLength = 1;

/** Read a compact size number, checking that it is complete and minimal

  {
    encoded: <Encoded Number Buffer Object>
    [start]: <Start Reading at Offset Number>
  }

  @throws
  <ExpectedCompactSizeNumber Error>
  <ExpectedMinimallyEncodedCompactSizeNumber Error>

  @returns
  {
    bytes: <Encoded Number Byte Length Number>
    number: <Number BigInt>
  }
*/
module.exports = ({encoded, start}) => {
  const offset = start || defaultStart;

  if (offset >= encoded.length) {
    throw new Error('ExpectedCompactSizeNumber');
  }

  const marker = encoded[offset];

  const bytes = encodedByteLengths[marker] || singleByteLength;

  if (bytes === singleByteLength) {
    return {bytes, number: BigInt(marker)};
  }

  // A marker byte is followed by the little-endian bytes of the number
  if (offset + bytes > encoded.length) {
    throw new Error('ExpectedCompactSizeNumber');
  }

  const number = encoded
    .subarray(offset + singleByteLength, offset + bytes)
    .reduceRight((sum, byte) => (sum << shiftByte) + BigInt(byte), BigInt(0));

  // The number must use the shortest encoding that can represent it
  if (number < minimumNumbers[bytes]) {
    throw new Error('ExpectedMinimallyEncodedCompactSizeNumber');
  }

  return {bytes, number};
};
