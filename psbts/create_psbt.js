const {defaultTransactionVersionNumber} = require('./constants');
const encodeUnsignedPsbt = require('./encode_unsigned_psbt');
const {maxInt32} = require('./constants');
const {maxMoneyTokens} = require('./constants');
const {minInt32} = require('./constants');

const defaultSequenceNumber = 0xffffffff;
const {isArray} = Array;
const isHex = n => typeof n === 'string' && /^(?:[0-9a-f]{2})*$/i.test(n);
const isInt32 = n => Number.isInteger(n) && n >= minInt32 && n <= maxInt32;
const isTokens = n => Number.isSafeInteger(n) && n >= 0;
const isTxId = n => typeof n === 'string' && /^[0-9a-f]{64}$/i.test(n);
const isUint32 = n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
const noTimelock = 0;
const timelockSequenceNumber = 0xfffffffe;

/** Create a PSBT

  When a timelock is set, inputs without a sequence use a sequence that lets
  the timelock take effect

  {
    outputs: [{
      script: <Output ScriptPub Hex String>
      tokens: <Sending Tokens Number>
    }]
    [timelock]: <Set Lock Time on Transaction To Number>
    utxos: [{
      id: <Transaction Id Hex String>
      [sequence]: <Sequence Number>
      vout: <Output Index Number>
    }]
    [version]: <Transaction Version Number>
  }

  @throws
  <Error>

  @returns
  {
    psbt: <Partially Signed Bitcoin Transaction Hex Encoded String>
  }
*/
module.exports = ({outputs, timelock, utxos, version}) => {
  const outpoints = new Set();

  if (!isArray(outputs)) {
    throw new Error('ExpectedTransactionOutputsForNewPsbt');
  }

  if (!isArray(utxos)) {
    throw new Error('ExpectedTransactionInputsForNewPsbt');
  }

  // Every output has a whole and non-negative number of tokens
  outputs.forEach(output => {
    if (!output || !isTokens(output.tokens)) {
      throw new Error('ExpectedNonNegativeIntegerTokensForNewPsbtOutput');
    }
  });

  // An output script is complete hex, and it can be empty
  outputs.forEach(({script}) => {
    if (!isHex(script)) {
      throw new Error('ExpectedHexOutputScriptForNewPsbtOutput');
    }
  });

  const tokens = outputs.reduce((sum, output) => sum + output.tokens, 0);

  // The outputs cannot send more than every bitcoin there can be
  if (tokens > maxMoneyTokens) {
    throw new Error('UnexpectedOutputTokensAboveMaxMoneyForNewPsbt');
  }

  // Every utxo has the index of the output that it spends
  utxos.forEach(utxo => {
    if (!utxo || !isUint32(utxo.vout)) {
      throw new Error('ExpectedOutputIndexNumberForNewPsbtUtxo');
    }
  });

  // A transaction id is exactly 64 hex characters
  utxos.forEach(({id}) => {
    if (!isTxId(id)) {
      throw new Error('ExpectedTransactionIdHexStringForNewPsbtUtxo');
    }
  });

  // An outpoint can only be spent once
  utxos.forEach(({id, vout}) => {
    const outpoint = `${id.toLowerCase()}:${vout}`;

    if (outpoints.has(outpoint)) {
      throw new Error('UnexpectedDuplicateOutpointForNewPsbtUtxo');
    }

    return outpoints.add(outpoint);
  });

  // A sequence is optional, and when it is supplied it is 32 bits
  utxos.forEach(({sequence}) => {
    if (sequence !== undefined && !isUint32(sequence)) {
      throw new Error('ExpectedValidSequenceNumberForNewPsbtUtxo');
    }
  });

  if (timelock !== undefined && !isUint32(timelock)) {
    throw new Error('ExpectedValidTimelockNumberForNewPsbt');
  }

  if (version !== undefined && !isInt32(version)) {
    throw new Error('ExpectedValidVersionNumberForNewPsbt');
  }

  const locktime = timelock === undefined ? noTimelock : timelock;

  // A timelock only takes effect when an input sequence is not final
  const sequence = !locktime ? defaultSequenceNumber : timelockSequenceNumber;

  // Construct the unsigned inputs, each with its own sequence or the default
  const inputs = utxos.map(n => ({
    id: n.id,
    sequence: n.sequence === undefined ? sequence : n.sequence,
    vout: n.vout,
  }));

  const isFinal = inputs.every(n => n.sequence === defaultSequenceNumber);

  // Exit early when every input explicitly disables the requested timelock
  if (!!locktime && !!inputs.length && isFinal) {
    throw new Error('ExpectedNonFinalSequenceForTimelockToTakeEffect');
  }

  return encodeUnsignedPsbt({
    inputs,
    locktime,
    outputs,
    version: version === undefined ? defaultTransactionVersionNumber : version,
  });
};
