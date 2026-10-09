const {componentsOfTransaction} = require('@alexbosworth/blockchain');

const encodeUnsignedPsbt = require('./encode_unsigned_psbt');
const {encodeWitnessStack} = require('./../transactions');
const extendPsbt = require('./extend_psbt');
const {isNestedWitnessSpend} = require('./../spends');
const {isP2shScript} = require('./../utxos');
const {isWitnessProgram} = require('./../utxos');
const {transactionId} = require('./../transactions');
const {witnessProgram} = require('./../utxos');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const isHex = n => typeof n === 'string' && /^(?:[0-9a-f]{2})*$/i.test(n);
const {isSafeInteger} = Number;
const taprootKeyByteLength = 32;
const taprootVersion = 1;

/** Convert a raw transaction into a finalized PSBT ready for extraction

  An input that spends a legacy output needs the full previous transaction
  that it spends from. An input that spends a witness output, including a
  P2SH output spent with a push of the witness program that it hashes, can
  instead have a UTXO reference to the output that it spends. A UTXO
  reference given along with the previous transaction must describe the same
  output.

  {
    spending: [<Spending Transaction Hex String>]
    transaction: <Hex Encoded Transaction String>
    [utxos]: [{
      script_pub: <Output Script Hex String>
      tokens: <Output Tokens Number>
      vin: <Input Index Number>
    }]
  }

  @throws
  <Error>

  @returns
  {
    psbt: <Finalized PSBT Hex String>
  }
*/
module.exports = ({spending, transaction, utxos}) => {
  if (!isArray(spending)) {
    throw new Error('ExpectedArrayOfSpendingTransactionsToUnextractTx');
  }

  if (!transaction) {
    throw new Error('ExpectedTransactionToUnextractIntoFinalizedPsbt');
  }

  if (utxos !== undefined && !isArray(utxos)) {
    throw new Error('ExpectedArrayOfUtxoReferencesToUnextractTx');
  }

  const references = new Map();
  const spends = new Map();

  // Index the UTXO references by the input that spends them, once
  (utxos || []).forEach(reference => {
    if (!isSafeInteger(reference.vin) || reference.vin < 0) {
      throw new Error('ExpectedInputIndexForUtxoReference');
    }

    // Hex that is not whole bytes would be cut short when it is encoded
    if (!isHex(reference.script_pub)) {
      throw new Error('ExpectedHexScriptPubForUtxoReference');
    }

    if (!isSafeInteger(reference.tokens) || reference.tokens < 0) {
      throw new Error('ExpectedNonNegativeTokensForUtxoReference');
    }

    // The first reference to the output an input spends is the one used
    if (references.has(reference.vin)) {
      return;
    }

    return references.set(reference.vin, {
      script_pub: reference.script_pub.toLowerCase(),
      tokens: reference.tokens,
    });
  });

  // Index the spending transactions by their ids, parsing each one once
  spending.forEach(hex => {
    let spend;

    try {
      spend = componentsOfTransaction({transaction: hex});
    } catch (err) {
      throw new Error('ExpectedValidSpendingTransactionToUnextractTx');
    }

    const {id} = transactionId(spend);

    // The first transaction with an id is the one used
    if (spends.has(id)) {
      return;
    }

    return spends.set(id, {outputs: spend.outputs, transaction: hex});
  });

  const tx = componentsOfTransaction({transaction});

  const outputs = tx.outputs;

  // The unsigned transaction keeps the exact sequences and lock time
  const {psbt} = encodeUnsignedPsbt({
    outputs,
    inputs: tx.inputs.map(({id, sequence, vout}) => ({id, sequence, vout})),
    locktime: tx.locktime,
    version: tx.version,
  });

  const inputs = tx.inputs.map(({id, script, vout, witness = []}, vin) => {
    const reference = references.get(vin);
    const spend = spends.get(id);

    if (!spend && !reference) {
      throw new Error('ExpectedSpendingTransactionsForAllInputs');
    }

    const spent = !!spend ? spend.outputs[vout] : undefined;

    // A previous transaction must have the output that the input spends
    if (!!spend && !spent) {
      throw new Error('ExpectedSpentOutputInSpendingTransaction');
    }

    // A reference must describe the output in the previous transaction
    if (!!spend && !!reference) {
      const isSameScript = reference.script_pub === spent.script;
      const isSameTokens = reference.tokens === spent.tokens;

      if (!isSameScript || !isSameTokens) {
        throw new Error('UtxoReferenceDoesNotMatchSpendingTransaction');
      }
    }

    const utxo = reference || {script_pub: spent.script, tokens: spent.tokens};

    const spentScript = hexAsBuffer(utxo.script_pub);

    const hasWitness = !!witness.length;
    const isP2sh = isP2shScript({script: spentScript});
    const isProgram = isWitnessProgram({script: spentScript});

    // A P2SH output nesting a witness program is spent by a push of it
    const isNested = isNestedWitnessSpend({script, spent: spentScript});

    // A witness input spends a witness program, nested in P2SH or not
    const isWitnessInput = isP2sh ? isNested : hasWitness || isProgram;

    // A legacy input is funded by the full transaction it spends from
    if (!isWitnessInput && !spend) {
      throw new Error('ExpectedSpendingTransactionForLegacyInput');
    }

    const {program, version} = witnessProgram({script: spentScript});

    const isVersionOne = version === taprootVersion;

    // A taproot output is a version 1 witness program of a 32 byte key
    const isTaproot = isVersionOne && program.length === taprootKeyByteLength;

    const elements = witness.map(hexAsBuffer);

    const stack = encodeWitnessStack({elements});

    // Taproot inputs are funded by their witness UTXO alone
    const fullTx = !!spend && !isTaproot ? spend.transaction : undefined;

    return {
      // Without a witness the scriptSig is final, even when it is empty
      final_scriptsig: !!script || !hasWitness ? script : undefined,
      final_scriptwitness: hasWitness ? bufferAsHex(stack.witness) : undefined,
      non_witness_utxo: fullTx,
      witness_utxo: isWitnessInput ? utxo : undefined,
    };
  });

  return extendPsbt({inputs, psbt});
};
