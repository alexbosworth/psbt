const {transactionFromComponents} = require('@alexbosworth/blockchain');

const decodePsbt = require('./decode_psbt');
const {legacyTransactionComponents} = require('./../transactions');
const {parseWitnessElements} = require('./../transactions');

const bufferAsHex = buffer => buffer.toString('hex');
const emptyScriptSig = '';
const emptyScriptWitness = '';
const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Extract a transaction from a finalized PSBT

  Every input needs a final scriptSig or a final script witness, either of
  which can be empty. A transaction needs inputs and outputs to be extracted.

  The transaction is serialized with witnesses when an input has a final
  script witness with at least one element, even if the element is empty.

  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }

  @throws
  <Extract Transaction Error>

  @returns
  {
    transaction: <Hex Serialized Transaction String>
  }
*/
module.exports = ({psbt}) => {
  const decoded = decodePsbt({psbt});

  const tx = legacyTransactionComponents({
    transaction: decoded.unsigned_transaction,
  });

  // A transaction without inputs would be read as a witness transaction
  if (!tx.inputs.length) {
    throw new Error('ExpectedInputsToExtractTransaction');
  }

  // A transaction without outputs can never be valid
  if (!tx.outputs.length) {
    throw new Error('ExpectedOutputsToExtractTransaction');
  }

  // Attach every input's finalized scriptsig and witness to form the inputs
  const inputs = tx.inputs.map((txIn, vin) => {
    const input = decoded.inputs[vin];

    // An empty final script is still a final script
    const hasScriptSig = input.final_scriptsig !== undefined;
    const hasWitness = input.final_scriptwitness !== undefined;

    if (!hasScriptSig && !hasWitness) {
      throw new Error('ExpectedFinalScriptSigsAndWitnesses');
    }

    const scriptWitness = input.final_scriptwitness || emptyScriptWitness;

    // Split the final script witness into elements by their stated lengths
    const {elements} = parseWitnessElements({
      encoded: hexAsBuffer(scriptWitness),
    });

    const witness = elements.map(bufferAsHex);

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
