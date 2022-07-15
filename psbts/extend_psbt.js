const BN = require('bn.js');
const {encode} = require('varuint-bitcoin');

const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
const {encodeSignature} = require('./../signatures');
const {encodeDerivations} = require('./../bip32');
const {Transaction} = require('./../tokens');
const types = require('./types');

const {concat} = Buffer;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const {fromHex} = Transaction;
const sighashAsBuffer = n => new BN(n, 10).toArrayLike(Buffer, 'le', 4);
const tokensAsBuffer = n => new BN(n, 10).toArrayLike(Buffer, 'le', 8);

/** Extend a created PSBT template with additional fields

  {
    ecp: <ECPair Object>
    inputs: [{
      [bip32_derivations]: [{
        fingerprint: <Public Key Fingerprint Hex String>
        [leaf_hashes]: <Taproot Leaf Hash Hex String>
        path: <BIP 32 Child / Hardened Child / Index Derivation Path String>
        public_key: <Public Key Hex String>
      }]
      [final_scriptsig]: <Final ScriptSig Hex String>
      [final_scriptwitness]: <Final Script Witness Hex String>
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
    psbt: <Template BIP 174 Encoded PSBT String>
  }

  @returns
  {
    psbt: <Extended PSBT Hex String>
  }
*/
module.exports = args => {
  if (!args.ecp) {
    throw new Error('ExpectedEcpairObjectToExtendPsbt');
  }

  if (!isArray(args.inputs)) {
    throw new Error('ExpectedArrayOfInputMetadataToExtendPsbt');
  }

  if (!args.psbt) {
    throw new Error('ExpectedPsbtToExtend');
  }

  const decoded = decodePsbt({ecp: args.ecp, psbt: args.psbt});
  const pairs = [];

  const tx = fromHex(decoded.unsigned_transaction);

  // The transaction in network serialization
  pairs.push({
    type: hexAsBuffer(types.global.unsigned_tx),
    value: tx.toBuffer(),
  });

  // End of global type values
  pairs.push({separator: true});

  // Iterate through transaction inputs and fill in values
  tx.ins.forEach(({hash, index, sequence}, vin) => {
    const input = args.inputs[vin];

    // BIP 32 data for keys involved in signing for this input
    if (!!input.bip32_derivations) {
      const {legacy, taproot} = encodeDerivations({
        bip32_derivations: input.bip32_derivations,
      });

      legacy.forEach(({key, value}) => {
        return pairs.push({
          type: hexAsBuffer(types.input.bip32_derivation + key),
          value: hexAsBuffer(value),
        });
      });

      taproot.forEach(({key, value}) => {
        return pairs.push({
          type: hexAsBuffer(types.input.tap_bip32_derivation + key),
          value: hexAsBuffer(value),
        });
      });
    }

    // The Finalized scriptSig contains a fully constructed scriptSig
    if (!!input.final_scriptsig) {
      pairs.push({
        type: hexAsBuffer(types.input.final_scriptsig),
        value: hexAsBuffer(input.final_scriptsig),
      });
    }

    // The Finalized scriptWitness contains a fully constructed scriptWitness.
    if (!!input.final_scriptwitness) {
      pairs.push({
        type: hexAsBuffer(types.input.final_scriptwitness),
        value: hexAsBuffer(input.final_scriptwitness),
      });
    }

    // The transaction in network serialization format the current input spends
    if (!!input.non_witness_utxo) {
      pairs.push({
        type: hexAsBuffer(types.input.non_witness_utxo),
        value: hexAsBuffer(input.non_witness_utxo),
      });
    }

    // The signature as would be pushed to the stack from a scriptSig/witness
    if (isArray(input.partial_sig)) {
      input.partial_sig.forEach(partialSig => {
        return pairs.push({
          type: hexAsBuffer(types.input.partial_sig + partialSig.public_key),
          value: encodeSignature({
            flag: partialSig.hash_type,
            signature: partialSig.signature,
          }),
        });
      });
    }

    // The redeemScript for this input if it has one
    if (!!input.redeem_script) {
      pairs.push({
        type: hexAsBuffer(types.input.redeem_script),
        value: hexAsBuffer(input.redeem_script),
      });
    }

    // Sighash used to sign this input
    if (input.sighash_type !== undefined) {
      pairs.push({
        type: hexAsBuffer(types.input.sighash_type),
        value: sighashAsBuffer(input.sighash_type),
      });
    }

    // The taproot key signature
    if (!!input.taproot_key_spend_sig) {
      pairs.push({
        value: hexAsBuffer(input.taproot_key_spend_sig),
        type: hexAsBuffer(types.input.tap_key_sig),
      });
    }

    // The witnessScript for this input if it has one.
    if (!!input.witness_script) {
      pairs.push({
        type: hexAsBuffer(types.input.witness_script),
        value: hexAsBuffer(input.witness_script),
      });
    }

    // Witness UTXO being spent by this input
    if (!!input.witness_utxo) {
      const script = hexAsBuffer(input.witness_utxo.script_pub);
      const tokens = tokensAsBuffer(input.witness_utxo.tokens);

      pairs.push({
        type: hexAsBuffer(types.input.witness_utxo),
        value: concat([tokens, encode(script.length), script]),
      });
    }

    // Input pairs termination
    return pairs.push({separator: true});
  });

  // Iterate through the transaction outputs and fill in values
  tx.outs.forEach(({script, value}) => {
    // Output pairs termination
    return pairs.push({separator: true});
  });

  return encodePsbt({pairs});
};
