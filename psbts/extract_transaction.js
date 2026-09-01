const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');
const {transactionFromComponents} = require('@alexbosworth/blockchain');

const decodePsbt = require('./decode_psbt');
const numberAsBuffer = require('./number_as_buffer');

const asElements = script => scriptAsScriptElements({script}).elements;
const bufferAsHex = buffer => buffer.toString('hex');
const emptyScriptSig = '';
const emptyScriptWitness = '';
const emptyStackElement = '';
const {isBuffer} = Buffer;

/** Extract a transaction from a finalized PSBT

  {
    ecp: <ECPair Object>
    psbt: <BIP 174 Encoded PSBT Hex String>
  }

  @throws
  <Extract Transaction Error>

  @returns
  {
    transaction: <Hex Serialized Transaction String>
  }
*/
module.exports = ({ecp, psbt}) => {
  let decoded;

  try {
    decoded = decodePsbt({ecp, psbt});
  } catch (err) {
    throw err;
  }

  const tx = componentsOfTransaction({
    transaction: decoded.unsigned_transaction,
  });

  // Attach every input's finalized scriptsig and witness to form the inputs
  const inputs = tx.inputs.map((txIn, vin) => {
    const input = decoded.inputs[vin];

    if (!input.final_scriptsig && !input.final_scriptwitness) {
      throw new Error('ExpectedFinalScriptSigsAndWitnesses');
    }

    const scriptWitness = input.final_scriptwitness || emptyScriptWitness;

    // Convert the final script witness into witness stack elements
    const witness = asElements(scriptWitness).map(element => {
      if (!element) {
        return emptyStackElement;
      }

      if (isBuffer(element)) {
        return bufferAsHex(element);
      }

      return bufferAsHex(numberAsBuffer({number: element}));
    });

    return {
      witness,
      id: txIn.id,
      script: input.final_scriptsig || emptyScriptSig,
      sequence: txIn.sequence,
      vout: txIn.vout,
    };
  });

  return transactionFromComponents({
    inputs,
    locktime: tx.locktime,
    outputs: tx.outputs,
    version: tx.version,
  });
};
