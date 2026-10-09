const {defaultTapSigHashType} = require('./constants');
const {schnorrSignatureByteLength} = require('./constants');

/** Get the sighash type of a taproot signature

  A signature without a sighash type byte uses the default sighash type

  {
    signature: <Taproot Signature Buffer Object>
  }

  @returns
  {
    hash_type: <Signature Sighash Type Number>
  }
*/
module.exports = ({signature}) => {
  if (signature.length === schnorrSignatureByteLength) {
    return {hash_type: defaultTapSigHashType};
  }

  return {hash_type: signature.at(-1)};
};
