/** Encode a tokens value as an unsigned 64-bit little-endian buffer

  {
    tokens: <Tokens Number>
  }

  @returns
  <Tokens Value Buffer Object>
*/
module.exports = ({tokens}) => {
  const value = Buffer.alloc(8);

  value.writeBigUInt64LE(BigInt(tokens));

  return value;
};
