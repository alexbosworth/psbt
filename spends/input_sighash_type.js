const {taprootSighashType} = require('./../signatures');
const types = require('./../psbts/types');

const typeOf = key => key.subarray(0, 1).toString('hex');

/** Get the sighash type that an input gets from the signatures it has

  An input that has a sighash type keeps it, so it gets no other one. An input
  without one gets the sighash type that all of its signatures share, or none
  when its signatures use different sighash types.

  {
    pairs: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
  }

  @returns
  {
    [sighash_type]: <Sighash Type Shared By the Signatures Number>
  }
*/
module.exports = ({pairs}) => {
  const hashTypes = new Set();

  // Exit early when the input already has a sighash type
  if (!!pairs.find(n => typeOf(n.type) === types.input.sighash_type)) {
    return {};
  }

  pairs.forEach(({type, value}) => {
    const keyType = typeOf(type);

    const isKeySpendSig = keyType === types.input.tap_key_sig;
    const isScriptSpendSig = keyType === types.input.tap_script_sig;

    // A partial signature ends with the sighash type that it signed with
    if (keyType === types.input.partial_sig) {
      return hashTypes.add(value.at(-1));
    }

    // Exit early when the pair is not a taproot signature
    if (!isKeySpendSig && !isScriptSpendSig) {
      return;
    }

    const {hash_type} = taprootSighashType({signature: value});

    return hashTypes.add(hash_type);
  });

  // Exit early when there is not exactly one sighash type for the signatures
  if (hashTypes.size !== 1) {
    return {};
  }

  const [sighash] = hashTypes;

  return {sighash_type: sighash};
};
