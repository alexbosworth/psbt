const {checkInputSighashTypes} = require('./../checks');
const {encodeWitnessStack} = require('./../transactions');
const finalScripts = require('./final_scripts');
const {inputSignatureHash} = require('./../sighash');
const inputSpend = require('./input_spend');
const {isP2shScript} = require('./../utxos');
const {isValidSchnorrSignature} = require('./../signatures');
const {isValidSignature} = require('./../signatures');
const mergePairs = require('./../psbts/merge_pairs');
const paidKeySignatures = require('./paid_key_signatures');
const {taprootOutputKey} = require('./../utxos');
const {taprootSighashType} = require('./../signatures');
const {taprootSignatureHash} = require('./../sighash');
const types = require('./../psbts/types');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const hexOf = n => n === undefined ? n : n.toString('hex');
const maxPushByteLength = 520;
const typeOf = pair => pair.type.subarray(0, 1).toString('hex');

/** Finalize the key-value pairs of a PSBT input

  Signatures of the keys that the spending script pays to are checked against
  the signature hash of the input, and only valid signatures are used. A P2SH
  redeem script can be at most 520 bytes, the most that a scriptSig can push.

  {
    hashes: {
      outputs: <Hash of All Outputs Buffer Object>
      prevouts: <Hash of All Spent Outpoints Buffer Object>
      sequences: <Hash of All Input Sequences Buffer Object>
    }
    pairs: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
    parts: {
      locktime: <Serialized Lock Time Buffer Object>
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
      version: <Serialized Version Buffer Object>
    }
    spent: {
      [script]: <Spent Output Script Hex String>
      [tokens]: <Spent Output Tokens Number>
    }
    taproot_hashes: {
      [amounts]: <Hash of All Spent Output Amounts Buffer Object>
      outputs: <Hash of All Outputs Buffer Object>
      prevouts: <Hash of All Spent Outpoints Buffer Object>
      [scripts]: <Hash of All Spent Output Scripts Buffer Object>
      sequences: <Hash of All Input Sequences Buffer Object>
    }
    vin: <Input Index Number>
  }

  @throws
  <ExpectedAdditionalSignatures Error>
  <ExpectedOutputForInputSigningWithSigHashSingle Error>
  <ExpectedRedeemScriptToFinalizeInput Error>
  <ExpectedSignatureForPaidPublicKey Error>
  <ExpectedSignaturesForFinalizedTransaction Error>
  <ExpectedSpentOutputToFinalizeInput Error>
  <ExpectedSpentOutputsOfInputsToHashTaprootSignature Error>
  <ExpectedTaprootKeySpendSignatureToFinalizeInput Error>
  <ExpectedValidSignatureForPaidPublicKey Error>
  <ExpectedValidTaprootKeySpendSignatureToFinalizeInput Error>
  <ExpectedWitnessScriptToFinalizeInput Error>
  <UnexpectedOversizedRedeemScriptToFinalizeInput Error>
  <UnexpectedSigHashTypeForInputSignature Error>
  <UnsupportedScriptTypeToFinalize Error>

  @returns
  {
    pairs: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
  }
*/
module.exports = ({hashes, pairs, parts, spent, taproot_hashes, vin}) => {
  const finals = [];
  const signatures = [];
  const values = {};

  pairs.forEach(pair => {
    const type = typeOf(pair);

    // Each partial signature is for the public key in its key
    if (type === types.input.partial_sig) {
      return signatures.push({
        public_key: pair.type.subarray(1),
        signature: pair.value,
      });
    }

    return values[type] = pair.value;
  });

  const finalScriptSig = values[types.input.final_scriptsig];
  const finalScriptWitness = values[types.input.final_scriptwitness];

  const hasFinalScriptSig = finalScriptSig !== undefined;
  const hasFinalScriptWitness = finalScriptWitness !== undefined;
  const hasTapKeySig = !!values[types.input.tap_key_sig];
  const hasTapScriptSig = !!values[types.input.tap_script_sig];
  const hasSignatures = !!signatures.length || hasTapKeySig || hasTapScriptSig;

  // An input with a final scriptSig or script witness is already final
  const isFinal = hasFinalScriptSig || hasFinalScriptWitness;

  // Make sure that there is a signature when the input is finalized
  if (!isFinal && !hasSignatures) {
    throw new Error('ExpectedSignaturesForFinalizedTransaction');
  }

  // Signatures must use the sighash type of their input when it has one
  if (!isFinal) {
    checkInputSighashTypes({pairs});
  }

  // An input that is not final gets final scripts for the output it spends
  if (!isFinal) {
    // The output being spent decides how the input is finalized
    if (!spent.script) {
      throw new Error('ExpectedSpentOutputToFinalizeInput');
    }

    const outputScript = hexAsBuffer(spent.script);
    const redeemScript = values[types.input.redeem_script];
    const signedHashes = new Map();
    const witnessScript = values[types.input.witness_script];

    const isP2sh = isP2shScript({script: outputScript});

    // A P2SH redeem script is pushed in the scriptSig, which limits pushes
    if (isP2sh && !!redeemScript && redeemScript.length > maxPushByteLength) {
      throw new Error('UnexpectedOversizedRedeemScriptToFinalizeInput');
    }

    // Signatures sign a hash of how the input spends the output
    const spend = inputSpend({
      spent,
      input: {
        redeem_script: hexOf(redeemScript),
        witness_script: hexOf(witnessScript),
      },
    });

    // Only signatures of the keys that the script pays to can satisfy it
    const {signatures: paid} = paidKeySignatures({
      signatures,
      script: spend.script,
    });

    // Each signature is checked against the hash of its sighash type
    const checked = paid.map(n => {
      const sighash = n.signature.at(-1);

      if (!signedHashes.has(sighash)) {
        const {hash} = inputSignatureHash({
          hashes,
          parts,
          sighash,
          vin,
          is_witness: spend.is_witness,
          script: spend.script,
          tokens: spend.tokens,
        });

        signedHashes.set(sighash, hash);
      }

      const isValid = isValidSignature({
        hash: signedHashes.get(sighash),
        public_key: n.public_key,
        signature: n.signature,
      });

      return {...n, is_valid: isValid};
    });

    const keySpendSig = values[types.input.tap_key_sig];
    let tapKeySig;

    const {output_key} = taprootOutputKey({script: spent.script});

    // A key spend signature is checked against the key of the taproot output
    if (!!output_key && !!keySpendSig) {
      const {hash_type} = taprootSighashType({signature: keySpendSig});

      const {hash} = taprootSignatureHash({
        parts,
        spent,
        vin,
        hashes: taproot_hashes,
        sighash: hash_type,
      });

      const isValid = isValidSchnorrSignature({
        hash,
        public_key: hexAsBuffer(output_key),
        signature: keySpendSig,
      });

      tapKeySig = {is_valid: isValid, signature: keySpendSig};
    }

    const scripts = finalScripts({
      redeem: redeemScript,
      script: outputScript,
      signatures: checked,
      tap_key_sig: tapKeySig,
      witness: witnessScript,
    });

    if (scripts.script_sig !== undefined) {
      finals.push({
        type: hexAsBuffer(types.input.final_scriptsig),
        value: scripts.script_sig,
      });
    }

    if (!!scripts.witness) {
      const {witness} = encodeWitnessStack({elements: scripts.witness});

      finals.push({
        type: hexAsBuffer(types.input.final_scriptwitness),
        value: witness,
      });
    }
  }

  // Remove the fields used for signing, then add the final scripts
  const kept = pairs.filter(pair => !types.signing.includes(typeOf(pair)));

  const {section} = mergePairs({
    order: types.order.input,
    pairs: finals,
    section: kept,
  });

  return {pairs: section};
};
