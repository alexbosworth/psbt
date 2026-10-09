const serializeOutpoint = require('./serialize_outpoint');
const serializeOutput = require('./serialize_output');
const {uint32AsBuffer} = require('./../transactions');

/** Serialize the parts of a transaction that signature hashes commit to

  {
    transaction: {
      inputs: [{
        id: <Spent Transaction Id Hex String>
        sequence: <Sequence Number>
        vout: <Spent Output Index Number>
      }]
      locktime: <Lock Time Number>
      outputs: [{
        script: <Output Script Hex String>
        tokens: <Output Tokens Number>
      }]
      version: <Version Number>
    }
  }

  @returns
  {
    locktime: <Serialized Lock Time Buffer Object>
    outpoints: [<Serialized Spent Outpoint Buffer Object>]
    outputs: [<Serialized Output Buffer Object>]
    sequences: [<Serialized Input Sequence Buffer Object>]
    version: <Serialized Version Buffer Object>
  }
*/
module.exports = ({transaction}) => {
  const version = Buffer.alloc(4);

  // The version is a signed number
  version.writeInt32LE(transaction.version);

  const sequences = transaction.inputs.map(({sequence}) => {
    return uint32AsBuffer({number: sequence});
  });

  return {
    sequences,
    version,
    locktime: uint32AsBuffer({number: transaction.locktime}),
    outpoints: transaction.inputs.map(n => serializeOutpoint(n)),
    outputs: transaction.outputs.map(n => serializeOutput(n)),
  };
};
