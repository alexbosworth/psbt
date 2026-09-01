const {transactionFromComponents} = require('@alexbosworth/blockchain');

const {defaultTransactionVersionNumber} = require('./constants');
const encodePsbt = require('./encode_psbt');
const types = require('./types');

const defaultSequenceNumber = 0xffffffff;
const emptyScriptSig = '';
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const type = Buffer.from(types.global.unsigned_tx, 'hex');

/** Create a PSBT

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

  @returns
  {
    psbt: <Partially Signed Bitcoin Transaction Hex Encoded String>
  }
*/
module.exports = ({outputs, timelock, utxos, version}) => {
  if (!isArray(outputs)) {
    throw new Error('ExpectedTransactionOutputsForNewPsbt');
  }

  if (!isArray(utxos)) {
    throw new Error('ExpectedTransactionInputsForNewPsbt');
  }

  // Construct the unsigned inputs that will be the basis of the PSBT
  const inputs = utxos.map(({id, vout}) => ({
    id,
    vout,
    script: emptyScriptSig,
    sequence: defaultSequenceNumber,
  }));

  // Set sequence numbers as necessary
  utxos
    .filter(({sequence}) => sequence !== undefined)
    .forEach(({sequence}, vin) => inputs[vin].sequence = sequence);

  // Serialize the unsigned transaction from its component parts
  const {transaction} = transactionFromComponents({
    inputs,
    outputs,
    locktime: timelock || Number(),
    version: version || defaultTransactionVersionNumber,
  });

  // Initialize the type value pairs with the transaction
  const pairs = [{type, value: hexAsBuffer(transaction)}, {separator: true}];

  // Each input and output is represented as an empty key value pair
  outputs.concat(utxos).forEach(({}) => pairs.push({separator: true}));

  return encodePsbt({pairs});
};
