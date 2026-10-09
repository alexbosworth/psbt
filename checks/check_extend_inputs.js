const {extendHexFields} = require('./constants');
const {isBip32Path} = require('./../bip32');
const {maxUint32} = require('./../psbts/constants');

const fingerprintHexLength = 8;
const hashTypeLimit = 255;
const {isArray} = Array;
const isHex = n => typeof n === 'string' && /^(?:[0-9a-f]{2})*$/i.test(n);
const isObject = n => !!n && typeof n === 'object' && !Array.isArray(n);
const {isSafeInteger} = Number;
const leafHashHexLength = 64;
const keyHexLengths = [64, 66, 130];
const signatureHexLength = 128;
const xOnlyKeyHexLength = 64;

/** Check the input metadata to extend a PSBT with before anything is encoded

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
    transaction: {
      inputs: [{
        id: <Spent Transaction Id Hex String>
        vout: <Spent Output Index Number>
      }]
    }
  }

  @throws
  <Error>
*/
module.exports = ({inputs, transaction}) => {
  const derivationKeys = new Set();
  const signatureKeys = new Set();

  // There is metadata for each input of the transaction
  if (inputs.length !== transaction.inputs.length) {
    throw new Error('ExpectedMetadataForEachInputToExtendPsbt');
  }

  inputs.forEach((input, vin) => {
    if (!isObject(input)) {
      throw new Error('ExpectedMetadataObjectForInputToExtendPsbt');
    }

    const derivations = input.bip32_derivations;
    const signatures = input.partial_sig;

    if (derivations !== undefined && !isArray(derivations)) {
      throw new Error('ExpectedArrayOfBip32DerivationsToExtendPsbt');
    }

    (derivations || []).forEach(derivation => {
      if (!isObject(derivation)) {
        throw new Error('ExpectedBip32DerivationToExtendPsbt');
      }

      const {fingerprint} = derivation;
      const leafHashes = derivation.leaf_hashes;
      const publicKey = derivation.public_key;

      if (!isHex(fingerprint) || fingerprint.length !== fingerprintHexLength) {
        throw new Error('ExpectedFingerprintForBip32Derivation');
      }

      // A derivation without a path is of the master key itself
      if (derivation.path !== undefined && !isBip32Path(derivation)) {
        throw new Error('ExpectedValidPathForBip32Derivation');
      }

      if (!isHex(publicKey) || !keyHexLengths.includes(publicKey.length)) {
        throw new Error('ExpectedPublicKeyForBip32Derivation');
      }

      const derivationKey = `${vin}:${publicKey.toLowerCase()}`;

      // A public key can only have one derivation in an input
      if (derivationKeys.has(derivationKey)) {
        throw new Error('UnexpectedDuplicateBip32DerivationToExtendPsbt');
      }

      derivationKeys.add(derivationKey);

      // Exit early when there are no leaf hashes
      if (leafHashes === undefined) {
        return;
      }

      // Leaf hashes are only for the x-only public keys of taproot
      if (!isArray(leafHashes) || publicKey.length !== xOnlyKeyHexLength) {
        throw new Error('ExpectedLeafHashesForTaprootBip32Derivation');
      }

      leafHashes.forEach(hash => {
        if (!isHex(hash) || hash.length !== leafHashHexLength) {
          throw new Error('ExpectedLeafHashesForTaprootBip32Derivation');
        }

        return;
      });

      return;
    });

    if (signatures !== undefined && !isArray(signatures)) {
      throw new Error('ExpectedArrayOfPartialSignaturesToExtendPsbt');
    }

    (signatures || []).forEach(signature => {
      if (!isObject(signature) || !isHex(signature.public_key)) {
        throw new Error('ExpectedPublicKeyForPartialSignature');
      }

      const signatureKey = `${vin}:${signature.public_key.toLowerCase()}`;

      // A public key can only have one signature in an input
      if (signatureKeys.has(signatureKey)) {
        throw new Error('UnexpectedDuplicatePartialSignatureToExtendPsbt');
      }

      signatureKeys.add(signatureKey);

      // A signature is exactly its 32 byte r and s values
      if (!isHex(signature.signature)) {
        throw new Error('ExpectedSignatureForPartialSignature');
      }

      if (signature.signature.length !== signatureHexLength) {
        throw new Error('ExpectedSignatureForPartialSignature');
      }

      // The hash type is encoded as a single byte
      if (!isSafeInteger(signature.hash_type) || signature.hash_type < 0) {
        throw new Error('ExpectedHashTypeByteForPartialSignature');
      }

      if (signature.hash_type > hashTypeLimit) {
        throw new Error('ExpectedHashTypeByteForPartialSignature');
      }

      return;
    });

    // Scripts and other hex values can be empty, but must be whole bytes
    extendHexFields.forEach(field => {
      if (input[field] !== undefined && !isHex(input[field])) {
        throw new Error('ExpectedHexValueToExtendPsbt');
      }

      return;
    });

    const sighash = input.sighash_type;

    // The sighash type is encoded as an unsigned 32 bit number
    if (sighash !== undefined && (!isSafeInteger(sighash) || sighash < 0)) {
      throw new Error('ExpectedUnsignedIntegerSigHashTypeToExtendPsbt');
    }

    if (sighash !== undefined && sighash > maxUint32) {
      throw new Error('ExpectedUnsignedIntegerSigHashTypeToExtendPsbt');
    }

    // Exit early when there is no witness UTXO
    if (input.witness_utxo === undefined) {
      return;
    }

    const utxo = input.witness_utxo;

    if (!isObject(utxo) || !isHex(utxo.script_pub)) {
      throw new Error('ExpectedHexScriptPubForWitnessUtxoToExtendPsbt');
    }

    if (!isSafeInteger(utxo.tokens) || utxo.tokens < 0) {
      throw new Error('ExpectedNonNegativeTokensForWitnessUtxoToExtendPsbt');
    }

    return;
  });

  return;
};
