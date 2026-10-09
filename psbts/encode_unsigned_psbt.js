const {transactionFromComponents} = require('@alexbosworth/blockchain');

const encodePsbt = require('./encode_psbt');
const types = require('./types');

const emptyScriptSig = '';
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const type = Buffer.from(types.global.unsigned_tx, 'hex');

/** Encode a PSBT holding only an unsigned transaction and empty sections

  {
    inputs: [{
      id: <Transaction Id Hex String>
      sequence: <Sequence Number>
      vout: <Output Index Number>
    }]
    locktime: <Transaction Lock Time Number>
    outputs: [{
      script: <Output ScriptPub Hex String>
      tokens: <Sending Tokens Number>
    }]
    version: <Transaction Version Number>
  }

  @returns
  {
    psbt: <Partially Signed Bitcoin Transaction Hex Encoded String>
  }
*/
module.exports = ({inputs, locktime, outputs, version}) => {
  // Serialize the unsigned transaction from its component parts
  const {transaction} = transactionFromComponents({
    locktime,
    outputs,
    version,
    inputs: inputs.map(({id, sequence, vout}) => ({
      id,
      sequence,
      vout,
      script: emptyScriptSig,
    })),
  });

  // Initialize the type value pairs with the transaction
  const pairs = [{type, value: hexAsBuffer(transaction)}, {separator: true}];

  // Each input and output is represented as an empty section
  inputs.forEach(() => pairs.push({separator: true}));
  outputs.forEach(() => pairs.push({separator: true}));

  return encodePsbt({pairs});
};
