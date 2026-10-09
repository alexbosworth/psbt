const {taprootSighashType} = require('./../signatures');
const types = require('./../psbts/types');

const typeOf = key => key.subarray(0, 1).toString('hex');

/** Check that the signatures of a PSBT input use the input's sighash type

  An input without a sighash type can have signatures of any sighash type. A
  64 byte taproot signature uses the default sighash type.

  {
    pairs: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
  }

  @throws
  <UnexpectedSigHashTypeForInputSignature Error>
*/
module.exports = ({pairs}) => {
  const sighash = pairs.find(n => typeOf(n.type) === types.input.sighash_type);

  // Exit early when the input has no sighash type for signatures to use
  if (!sighash) {
    return;
  }

  const sighashType = sighash.value.readUInt32LE();

  pairs.forEach(({type, value}) => {
    const keyType = typeOf(type);

    const isKeySpendSig = keyType === types.input.tap_key_sig;
    const isPartialSig = keyType === types.input.partial_sig;
    const isScriptSpendSig = keyType === types.input.tap_script_sig;

    // A partial signature ends with the sighash type that it signed with
    if (isPartialSig && value.at(-1) !== sighashType) {
      throw new Error('UnexpectedSigHashTypeForInputSignature');
    }

    // Exit early when the pair is not a taproot signature
    if (!isKeySpendSig && !isScriptSpendSig) {
      return;
    }

    const {hash_type} = taprootSighashType({signature: value});

    if (hash_type !== sighashType) {
      throw new Error('UnexpectedSigHashTypeForInputSignature');
    }

    return;
  });

  return;
};
