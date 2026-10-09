const {compactIntAsNumber} = require('@alexbosworth/blockchain');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLengthHash = 32;
const byteLengthInt32 = 4;
const byteLengthInt64 = 8;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const maxTokens = BigInt(Number.MAX_SAFE_INTEGER);
const minByteLengthInput = 41;
const minByteLengthOutput = 9;
const times = n => [...Array(n).keys()];
const txHashAsTxId = hash => Buffer.from(hash).reverse().toString('hex');

/** Get the components of a transaction in the legacy serialization format

  {
    transaction: <Hex Encoded Transaction String>
  }

  @throws
  <Error>

  @returns
  {
    inputs: [{
      id: <Spending Transaction Id Hex String>
      script: <ScriptSig Script Hex String>
      sequence: <Sequence Number>
      vout: <Spending Transaction Output Index Number>
    }]
    locktime: <Timelock nLockTime Number>
    outputs: [{
      script: <ScriptPub Script Hex String>
      tokens: <Tokens Count Number>
    }]
    version: <Version Number>
  }
*/
module.exports = ({transaction}) => {
  const buffer = hexAsBuffer(transaction);
  let offset = 0;

  // Read bytes, making sure that they are all present
  const read = bytes => {
    if (bytes > buffer.length - offset) {
      throw new Error('ExpectedAdditionalTransactionDataToParse');
    }

    offset += bytes;

    return buffer.subarray(offset - bytes, offset);
  };

  // Read a compact size count or length
  const readCount = () => {
    const {bytes, number} = compactIntAsNumber({
      encoded: buffer,
      start: offset,
    });

    offset += bytes;

    return number;
  };

  // The version is a signed 32 bit number
  const version = read(byteLengthInt32).readInt32LE();

  // The inputs count follows directly, there is no marker and flag
  const inputsCount = readCount();

  if (inputsCount * minByteLengthInput > buffer.length - offset) {
    throw new Error('UnexpectedInputCountForTransactionDataLength');
  }

  const inputs = times(inputsCount).map(() => {
    const id = txHashAsTxId(read(byteLengthHash));
    const vout = read(byteLengthInt32).readUInt32LE();
    const script = bufferAsHex(read(readCount()));
    const sequence = read(byteLengthInt32).readUInt32LE();

    return {id, script, sequence, vout};
  });

  const outputsCount = readCount();

  if (outputsCount * minByteLengthOutput > buffer.length - offset) {
    throw new Error('UnexpectedOutputCountForTransactionDataLength');
  }

  const outputs = times(outputsCount).map(() => {
    const value = read(byteLengthInt64).readBigUInt64LE();

    // Values beyond the safe integer range cannot be represented as a Number
    if (value > maxTokens) {
      throw new Error('UnexpectedOutputValueInTransaction');
    }

    return {script: bufferAsHex(read(readCount())), tokens: Number(value)};
  });

  const locktime = read(byteLengthInt32).readUInt32LE();

  if (offset !== buffer.length) {
    throw new Error('UnexpectedDataAfterTransaction');
  }

  return {inputs, locktime, outputs, version};
};
