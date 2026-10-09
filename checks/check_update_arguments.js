const {decodeSignature} = require('./../signatures');
const {isBip32Path} = require('./../bip32');
const {maxUint32} = require('./../psbts/constants');
const types = require('./../psbts/types');

const fingerprintHexLength = 8;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const isHex = n => typeof n === 'string' && /^(?:[0-9a-f]{2})*$/i.test(n);
const isIndex = (n, count) => Number.isInteger(n) && n >= 0 && n < count;
const isTxId = n => typeof n === 'string' && /^[0-9a-f]{64}$/i.test(n);
const isUint32 = n => Number.isInteger(n) && n >= 0 && n <= maxUint32;

/** Check the arguments of a PSBT update before anything is encoded

  {
    transaction: {
      inputs: [{
        id: <Spent Transaction Id Hex String>
        vout: <Spent Output Index Number>
      }]
      outputs: [{
        script: <Output Script Hex String>
        tokens: <Output Tokens Number>
      }]
    }
    update: {
      [additional_attributes]: [{
        type: <Type Hex String>
        value: <Value Hex String>
        [vin]: <Input Index Number>
        [vout]: <Output Index Number>
      }]
      [bip32_derivations]: [{
        fingerprint: <BIP 32 Fingerprint of Parent's Key Hex String>
        [path]: <BIP 32 Derivation Path String>
        public_key: <Public Key Hex String>
      }]
      [redeem_scripts]: [<Hex Encoded Redeem Script String>]
      [sighashes]: [{
        id: <Transaction Id String>
        sighash: <Sighash Flag Number>
        vout: <Spending Output Index Number>
      }]
      [signatures]: [{
        [hash_type]: <Signature Hash Type Number>
        public_key: <Public Key Hex String>
        signature: <Signature Hex String>
        vin: <Signature Input Index Number>
      }]
      [taproot_inputs]: [{
        [key_spend_sig]: <Taproot Key Spend Signature Hex String>
        vin: <Input Index Number>
      }]
      [transactions]: [<Hex Encoded Transaction String>]
      [witness_scripts]: [<Witness Script Hex String>]
    }
  }

  @throws
  <Error>
*/
module.exports = ({transaction, update}) => {
  const derivationKeys = new Set();
  const inputsCount = transaction.inputs.length;
  const outputsCount = transaction.outputs.length;
  const sighashOutpoints = new Set();
  const signatureKeys = new Set();
  const taprootInputs = new Set();
  const spent = new Set(transaction.inputs.map(n => `${n.id}:${n.vout}`));

  const lists = [
    update.additional_attributes,
    update.bip32_derivations,
    update.redeem_scripts,
    update.sighashes,
    update.signatures,
    update.taproot_inputs,
    update.transactions,
    update.witness_scripts,
  ];

  // Lists of values are arrays when they are given
  lists.forEach(list => {
    if (list !== undefined && !isArray(list)) {
      throw new Error('ExpectedArrayOfValuesToUpdatePsbt');
    }

    return;
  });

  (update.additional_attributes || []).forEach(attribute => {
    if (!isHex(attribute.type) || !isHex(attribute.value)) {
      throw new Error('ExpectedHexKeyAndValueForAdditionalAttribute');
    }

    const hasInput = attribute.vin !== undefined;
    const hasOutput = attribute.vout !== undefined;

    // An attribute goes in the global section, an input, or an output
    if (hasInput && hasOutput) {
      throw new Error('ExpectedInputOrOutputIndexForAdditionalAttribute');
    }

    if (hasInput && !isIndex(attribute.vin, inputsCount)) {
      throw new Error('ExpectedInputIndexForAdditionalAttribute');
    }

    if (hasOutput && !isIndex(attribute.vout, outputsCount)) {
      throw new Error('ExpectedOutputIndexForAdditionalAttribute');
    }

    const isGlobal = !hasInput && !hasOutput;

    // The unsigned transaction of a PSBT cannot be changed by an update
    if (isGlobal && attribute.type === types.global.unsigned_tx) {
      throw new Error('UnexpectedUnsignedTransactionAttributeToUpdatePsbt');
    }

    return;
  });

  (update.bip32_derivations || []).forEach(derivation => {
    const {fingerprint} = derivation;

    if (!isHex(fingerprint) || fingerprint.length !== fingerprintHexLength) {
      throw new Error('ExpectedFingerprintForBip32Derivation');
    }

    // A derivation without a path is of the master key itself
    if (derivation.path !== undefined && !isBip32Path(derivation)) {
      throw new Error('ExpectedValidPathForBip32Derivation');
    }

    if (!isHex(derivation.public_key)) {
      throw new Error('ExpectedHexPublicKeyForBip32Derivation');
    }

    const publicKey = derivation.public_key.toLowerCase();

    // A public key can only have one derivation in an update
    if (derivationKeys.has(publicKey)) {
      throw new Error('UnexpectedDuplicateBip32DerivationToUpdatePsbt');
    }

    derivationKeys.add(publicKey);

    return;
  });

  (update.redeem_scripts || []).forEach(script => {
    if (!isHex(script)) {
      throw new Error('ExpectedHexRedeemScriptToUpdatePsbt');
    }

    return;
  });

  (update.sighashes || []).forEach(sighash => {
    if (!isTxId(sighash.id) || !isUint32(sighash.vout)) {
      throw new Error('ExpectedOutpointForSigHashToUpdatePsbt');
    }

    if (!isUint32(sighash.sighash)) {
      throw new Error('ExpectedUnsignedIntegerSigHashToUpdatePsbt');
    }

    const outpoint = `${sighash.id.toLowerCase()}:${sighash.vout}`;

    // The sighash must be for an outpoint that an input spends
    if (!spent.has(outpoint)) {
      throw new Error('ExpectedSpentOutpointForSigHashToUpdatePsbt');
    }

    // An outpoint can only have one sighash in an update
    if (sighashOutpoints.has(outpoint)) {
      throw new Error('UnexpectedDuplicateSigHashToUpdatePsbt');
    }

    sighashOutpoints.add(outpoint);

    return;
  });

  (update.signatures || []).forEach(signature => {
    if (!isIndex(signature.vin, inputsCount)) {
      throw new Error('ExpectedInputIndexForSignatureToUpdatePsbt');
    }

    if (!isHex(signature.public_key)) {
      throw new Error('ExpectedHexPublicKeyForSignatureToUpdatePsbt');
    }

    if (!isHex(signature.signature)) {
      throw new Error('ExpectedHexSignatureToUpdatePsbt');
    }

    const publicKey = signature.public_key.toLowerCase();

    // A public key can only have one signature for an input in an update
    if (signatureKeys.has(`${signature.vin}:${publicKey}`)) {
      throw new Error('UnexpectedDuplicateSignatureToUpdatePsbt');
    }

    signatureKeys.add(`${signature.vin}:${publicKey}`);

    let decoded;

    // The signature ends with the sighash type that it signed with
    try {
      decoded = decodeSignature({signature: hexAsBuffer(signature.signature)});
    } catch (err) {
      throw new Error('ExpectedValidSignatureToUpdatePsbt');
    }

    // A stated sighash type must be the type that the signature has
    if (signature.hash_type === undefined) {
      return;
    }

    if (!isUint32(signature.hash_type)) {
      throw new Error('ExpectedUnsignedIntegerHashTypeForSignature');
    }

    if (signature.hash_type !== decoded.hash_type) {
      throw new Error('UnexpectedHashTypeForSignatureToUpdatePsbt');
    }

    return;
  });

  (update.taproot_inputs || []).forEach(input => {
    if (!isIndex(input.vin, inputsCount)) {
      throw new Error('ExpectedInputIndexForTaprootInputToUpdatePsbt');
    }

    // An input can only have one taproot input in an update
    if (taprootInputs.has(input.vin)) {
      throw new Error('UnexpectedDuplicateTaprootInputToUpdatePsbt');
    }

    taprootInputs.add(input.vin);

    if (input.key_spend_sig !== undefined && !isHex(input.key_spend_sig)) {
      throw new Error('ExpectedHexKeySpendSignatureForTaprootInput');
    }

    return;
  });

  (update.transactions || []).forEach(transaction => {
    if (!isHex(transaction)) {
      throw new Error('ExpectedHexTransactionToUpdatePsbt');
    }

    return;
  });

  (update.witness_scripts || []).forEach(script => {
    if (!isHex(script)) {
      throw new Error('ExpectedHexWitnessScriptToUpdatePsbt');
    }

    return;
  });

  return;
};
