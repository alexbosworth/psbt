const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {idForTransaction} = require('@alexbosworth/blockchain');
const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const createPsbt = require('./create_psbt');
const extendPsbt = require('./extend_psbt');
const {pushData} = require('./../script');

const bufferAsHex = buffer => buffer.toString('hex');
const {concat} = Buffer;
const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const isTaproot = n => n.length === 68 && parseInt(n.slice(0, 2), 16) >= 1;
const transactionId = hex => idForTransaction({transaction: hex}).id;
const txOuts = tx => componentsOfTransaction({transaction: tx}).outputs;

/** Convert a raw transaction into a finalized PSBT ready for extraction

  {
    ecp: <ECPair Object>
    spending: [<Spending Transaction Hex String>]
    transaction: <Hex Encoded Transaction String>
    [utxos]: [{
      script_pub: <Output Script Hex String>
      tokens: <Output Tokens Number>
      vin: <Input Index Number>
    }]
  }
*/
module.exports = ({ecp, spending, transaction, utxos}) => {
  if (!ecp) {
    throw new Error('ExpectedEcpairLibraryToUnextractTransaction');
  }

  if (!isArray(spending)) {
    throw new Error('ExpectedArrayOfSpendingTransactionsToUnextractTx');
  }

  if (!transaction) {
    throw new Error('ExpectedTransactionToUnextractIntoFinalizedPsbt');
  }

  const tx = componentsOfTransaction({transaction});

  const outputs = tx.outputs;

  const {psbt} = createPsbt({
    outputs,
    timelock: tx.locktime,
    utxos: tx.inputs.map(({id, sequence, vout}) => ({sequence, id, vout})),
    version: tx.version,
  });

  const inputs = tx.inputs.map(({id, script, vout, witness = []}, vin) => {
    const reference = (utxos || []).find(n => n.vin === vin);
    const spend = spending.find(n => transactionId(n) === id);

    if (!spend && !reference) {
      throw new Error('ExpectedSpendingTransactionsForAllInputs');
    }

    const wScript = concat([]
      .concat(encode(witness.length))
      .concat(witness.map(data => pushData({data: hexAsBuffer(data)}))));

    const utxo = reference || {
      script_pub: txOuts(spend)[vout].script,
      tokens: txOuts(spend)[vout].tokens,
    };

    return {
      non_witness_utxo: isTaproot(utxo.script_pub) ? undefined : spend,
      final_scriptsig: script || undefined,
      final_scriptwitness: !!witness.length ? bufferAsHex(wScript) : undefined,
      witness_utxo: !!witness.length ? utxo : undefined,
    };
  });

  return extendPsbt({ecp, inputs, psbt});
};
