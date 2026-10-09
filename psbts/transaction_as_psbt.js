const {componentsOfTransaction} = require('@alexbosworth/blockchain');

const encodeUnsignedPsbt = require('./encode_unsigned_psbt');
const extractTransaction = require('./extract_transaction');
const finalizePsbt = require('./finalize_psbt');
const {signedSpend} = require('./../spends');
const {transactionId} = require('./../transactions');
const updatePsbt = require('./update_psbt');

/** Convert a signed transaction to a signed PSBT

  Inputs can spend P2PKH, P2WPKH, and nested P2WPKH outputs, and P2SH, P2WSH,
  nested P2WSH, and bare outputs with a script that pays to a public key, to
  a public key hash, or to a multisig where every key signs. Other spends are
  rejected, as is a conversion that would not finalize to the same
  transaction.

  The PSBT keeps the exact locktime and input sequences of the transaction.

  {
    spending: [<Spending Transaction Hex String>]
    transaction: <Hex Encoded Transaction String>
  }

  @throws
  <Error>

  @returns
  {
    psbt: <Signed PSBT String>
  }
*/
module.exports = ({spending, transaction}) => {
  const fundings = new Map();
  const redeemScripts = [];
  const signatures = [];
  const tx = componentsOfTransaction({transaction});
  const witnessScripts = [];

  // Index the spending transactions by id, parsing each one only once
  spending.forEach(hex => {
    const funding = componentsOfTransaction({transaction: hex});

    const {id} = transactionId(funding);

    return fundings.set(id, funding.outputs);
  });

  // The unsigned transaction keeps the exact sequences and lock time
  const {psbt} = encodeUnsignedPsbt({
    inputs: tx.inputs.map(({id, sequence, vout}) => ({id, sequence, vout})),
    locktime: tx.locktime,
    outputs: tx.outputs,
    version: tx.version,
  });

  // Each input has its own scripts and signatures, found from its spent output
  tx.inputs.forEach((input, vin) => {
    const outputs = fundings.get(input.id);

    if (!outputs || !outputs[input.vout]) {
      throw new Error('ExpectedSpentOutputToConvertTransactionToPsbt');
    }

    const spend = signedSpend({
      script: input.script,
      spent: outputs[input.vout].script,
      witness: input.witness || [],
    });

    if (spend.redeem_script !== undefined) {
      redeemScripts.push(spend.redeem_script);
    }

    if (spend.witness_script !== undefined) {
      witnessScripts.push(spend.witness_script);
    }

    spend.signatures.forEach(n => signatures.push({...n, vin}));

    return;
  });

  const converted = updatePsbt({
    psbt,
    signatures,
    redeem_scripts: redeemScripts,
    transactions: spending,
    witness_scripts: witnessScripts,
  });

  // The PSBT must keep everything needed to finalize the same transaction
  const finalized = finalizePsbt({psbt: converted.psbt});

  const extracted = extractTransaction({psbt: finalized.psbt});

  if (extracted.transaction !== transaction.toLowerCase()) {
    throw new Error('ExpectedConvertedPsbtToFinalizeToSameTransaction');
  }

  return {psbt: converted.psbt};
};
