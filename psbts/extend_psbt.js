const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const {checkExtendInputs} = require('./../checks');
const {checkInputSighashTypes} = require('./../checks');
const decodePsbt = require('./decode_psbt');
const {encodeDerivations} = require('./../bip32');
const encodePsbt = require('./encode_psbt');
const {encodeSignature} = require('./../signatures');
const {legacyTransactionComponents} = require('./../transactions');
const psbtSections = require('./psbt_sections');
const sighashAsBuffer = require('./sighash_as_buffer');
const {tokensAsBuffer} = require('./../transactions');
const types = require('./types');

const bufferAsHex = buffer => buffer.toString('hex');
const {concat} = Buffer;
const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;

/** Extend a PSBT with additional input fields

  Existing values are kept, and added values replace existing values that
  have the same key.

  Signatures must use the sighash type of their input when it has one. A 64
  byte taproot signature uses the default sighash type.

  A final script witness is given as it is encoded in a PSBT: the count of
  witness elements, then each length prefixed element.

  {
    inputs: [{
      [bip32_derivations]: [{
        fingerprint: <Public Key Fingerprint Hex String>
        [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
        [path]: <BIP 32 Child / Hardened Child / Index Derivation Path String>
        public_key: <Public Key Hex String>
      }]
      [final_scriptsig]: <Final ScriptSig Hex String>
      [final_scriptwitness]: <Witness Elements With Count Hex String>
      [non_witness_utxo]: <Non-Witness Hex Encoded Transaction String>
      [partial_sig]: [{
        hash_type: <Signature Hash Type Number>
        public_key: <Public Key Hex String>
        signature: <ECDSA Signature Hex String>
      }]
      [redeem_script]: <Hex Encoded Redeem Script String>
      [sighash_type]: <Sighash Type Number>
      [taproot_key_spend_sig]: <Taproot Key Spend Signature Hex String>
      [witness_script]: <Witness Script Hex String>
      [witness_utxo]: {
        script_pub: <UTXO ScriptPub Hex String>
        tokens: <Tokens Number>
      }
    }]
    psbt: <BIP 174 Encoded PSBT String>
  }

  @throws
  <Error>

  @returns
  {
    psbt: <Extended PSBT Hex String>
  }
*/
module.exports = args => {
  if (!isArray(args.inputs)) {
    throw new Error('ExpectedArrayOfInputMetadataToExtendPsbt');
  }

  if (!args.psbt) {
    throw new Error('ExpectedPsbtToExtend');
  }

  const decoded = decodePsbt({psbt: args.psbt});
  const inputPairs = [];
  const pairs = [];

  const tx = legacyTransactionComponents({
    transaction: decoded.unsigned_transaction,
  });

  // The input metadata is checked before anything is encoded
  checkExtendInputs({inputs: args.inputs, transaction: tx});

  const {sections} = psbtSections({psbt: args.psbt});

  // The existing pairs of each section are kept
  const [globalPairs, ...maps] = sections;

  globalPairs.forEach(pair => pairs.push(pair));

  // End of global type values
  pairs.push({separator: true});

  // Iterate through transaction inputs and fill in values
  tx.inputs.forEach((txIn, vin) => {
    const input = args.inputs[vin];
    const values = [];

    // BIP 32 data for keys involved in signing for this input
    if (input.bip32_derivations !== undefined) {
      const {legacy, taproot} = encodeDerivations({
        bip32_derivations: input.bip32_derivations,
      });

      legacy.forEach(({key, value}) => {
        return values.push({
          type: hexAsBuffer(types.input.bip32_derivation + key),
          value: hexAsBuffer(value),
        });
      });

      taproot.forEach(({key, value}) => {
        return values.push({
          type: hexAsBuffer(types.input.tap_bip32_derivation + key),
          value: hexAsBuffer(value),
        });
      });
    }

    // The Finalized scriptSig contains a fully constructed scriptSig
    if (input.final_scriptsig !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.final_scriptsig),
        value: hexAsBuffer(input.final_scriptsig),
      });
    }

    // The Finalized scriptWitness contains a fully constructed scriptWitness.
    if (input.final_scriptwitness !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.final_scriptwitness),
        value: hexAsBuffer(input.final_scriptwitness),
      });
    }

    // The transaction in network serialization format the current input spends
    if (input.non_witness_utxo !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.non_witness_utxo),
        value: hexAsBuffer(input.non_witness_utxo),
      });
    }

    // The signature as would be pushed to the stack from a scriptSig/witness
    (input.partial_sig || []).forEach(partialSig => {
      return values.push({
        type: hexAsBuffer(types.input.partial_sig + partialSig.public_key),
        value: encodeSignature({
          flag: partialSig.hash_type,
          signature: partialSig.signature,
        }),
      });
    });

    // The redeemScript for this input if it has one, which can be empty
    if (input.redeem_script !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.redeem_script),
        value: hexAsBuffer(input.redeem_script),
      });
    }

    // Sighash used to sign this input
    if (input.sighash_type !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.sighash_type),
        value: sighashAsBuffer({sighash: input.sighash_type}),
      });
    }

    // The taproot key signature
    if (input.taproot_key_spend_sig !== undefined) {
      values.push({
        value: hexAsBuffer(input.taproot_key_spend_sig),
        type: hexAsBuffer(types.input.tap_key_sig),
      });
    }

    // The witnessScript for this input if it has one, which can be empty
    if (input.witness_script !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.witness_script),
        value: hexAsBuffer(input.witness_script),
      });
    }

    // Witness UTXO being spent by this input
    if (input.witness_utxo !== undefined) {
      const script = hexAsBuffer(input.witness_utxo.script_pub);
      const tokens = tokensAsBuffer({tokens: input.witness_utxo.tokens});

      values.push({
        type: hexAsBuffer(types.input.witness_utxo),
        value: concat([tokens, encode(script.length), script]),
      });
    }

    const added = new Set(values.map(n => bufferAsHex(n.type)));
    const section = [];

    // Existing pairs are kept unless an added value replaces them
    maps[vin].forEach(pair => {
      return added.has(bufferAsHex(pair.type)) ? null : section.push(pair);
    });

    values.forEach(pair => section.push(pair));

    inputPairs.push(section);

    section.forEach(pair => pairs.push(pair));

    // Input pairs termination
    return pairs.push({separator: true});
  });

  // Existing output pairs are kept
  maps.slice(tx.inputs.length).forEach(section => {
    section.forEach(pair => pairs.push(pair));

    // Output pairs termination
    return pairs.push({separator: true});
  });

  // The extended PSBT must be valid, including the values that were added
  const {psbt} = encodePsbt({pairs});

  // Signatures must use the sighash type of their input when it has one
  inputPairs.forEach(section => checkInputSighashTypes({pairs: section}));

  return {psbt};
};
