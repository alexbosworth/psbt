/** Decode an unsigned 64-bit little-endian tokens value as a number

  {
    value: <Tokens Value Buffer Object>
  }

  @throws
  <Expected Valid Tokens Number Error>

  @returns
  <Tokens Number>
*/
module.exports = ({value}) => {
  try {
    const tokens = value.readBigUInt64LE(0);

    if (tokens > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('TokensValueAboveMaximumSafeNumber');
    }

    return Number(tokens);
  } catch (err) {
    throw new Error('ExpectedValidTokensNumber');
  }
};
