const {encode} = require('varuint-bitcoin');

const createPsbt = require('./create_psbt');
const extendPsbt = require('./extend_psbt');
const {pushData} = require('./../script');
const {Transaction} = require('./../tokens');

const bufferAsHex = buffer => buffer.toString('hex');
const {concat} = Buffer;
const {fromHex} = Transaction;
const hashAsTransactionId = hash => hash.slice().reverse().toString('hex');
const internal = hash => hash.slice().reverse();
const {isArray} = Array;
const isTaproot = n => n.length === 68 && parseInt(n.slice(0, 2), 16) >= 1;

/** Convert a raw transaction into a finalized PSBT ready for extraction

  {
    ecp: <ECPair Object>
    spending: [<Spending Transaction Hex String>]
    transaction: <Hex Encoded Transaction String>
  }
*/
module.exports = ({ecp, spending, transaction}) => {
  if (!ecp) {
    throw new Error('ExpectedEcpairLibraryToUnextractTransaction');
  }

  if (!isArray(spending)) {
    throw new Error('ExpectedArrayOfSpendingTransactionsToUnextractTx');
  }

  if (!transaction) {
    throw new Error('ExpectedTransactionToUnextractIntoFinalizedPsbt');
  }

  const spendingTxs = spending.map(fromHex);
  const tx = fromHex(transaction);

  const outputs = tx.outs.map(({script, value}) => ({
    script: bufferAsHex(script),
    tokens: value,
  }));

  const utxos = tx.ins.map(({hash, index, sequence}) => ({
    sequence,
    id: hashAsTransactionId(hash),
    vout: index,
  }));

  const {psbt} = createPsbt({
    outputs,
    utxos,
    version: tx.version,
    timelock: tx.locktime,
  });

  const inputs = tx.ins.map(({hash, index, script, witness}) => {
    const spend = spendingTxs.find(n => n.getId() === bufferAsHex(hash));

    if (!spend) {
      throw new Error('ExpectedSpendingTransactionsForAllInputs');
    }

    const wScript = concat([]
      .concat(encode(witness.length))
      .concat(witness.map(data => pushData({data}))));

    const utxo = {
      script_pub: bufferAsHex(spend.outs[index].script),
      tokens: spend.outs[index].value,
    };

    return {
      non_witness_utxo: isTaproot(utxo.script_pub) ? undefined : spend.toHex(),
      final_scriptsig: bufferAsHex(script) || undefined,
      final_scriptwitness: !!witness.length ? bufferAsHex(wScript) : undefined,
      witness_utxo: !!witness.length ? utxo : undefined,
    };
  });

  return extendPsbt({ecp, inputs, psbt});
};
