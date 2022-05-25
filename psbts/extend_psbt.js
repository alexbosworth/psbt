const BN = require('bn.js');
const {encode} = require('varuint-bitcoin');

const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
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
    inputs: [{
      [bip32_derivations]: [{
        fingerprint: <Public Key Fingerprint Hex String>
        [leaf_hashes]: <Taproot Leaf Hash Hex String>
        path: <BIP 32 Child / Hardened Child / Index Derivation Path String>
        public_key: <Public Key Hex String>
      }]
      [sighash_type]: <Sighash Type Number>
      [witness_utxo]: {
        script_pub: <UTXO ScriptPub Hex String>
        tokens: <Tokens Number>
      }
    }]
    ecp: <ECPair Object>
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

    // Sighash used to sign this input
    if (input.sighash_type !== undefined) {
      pairs.push({
        type: hexAsBuffer(types.input.sighash_type),
        value: sighashAsBuffer(input.sighash_type),
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
