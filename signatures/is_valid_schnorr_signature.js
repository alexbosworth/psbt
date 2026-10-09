const {isXOnlyPoint} = require('tiny-secp256k1');
const {verifySchnorr} = require('tiny-secp256k1');

const {curveOrder} = require('./constants');
const {pointSize} = require('./constants');
const {schnorrSignatureByteLength} = require('./constants');

const order = Buffer.from(curveOrder, 'hex');

/** Determine if a taproot signature is a valid BIP 340 signature of a hash

  {
    hash: <Signed Hash Buffer Object>
    public_key: <X Only Public Key Buffer Object>
    signature: <Schnorr Signature With Optional Sighash Type Buffer Object>
  }

  @returns
  <Signature Is Valid Bool>
*/
module.exports = ({hash, public_key, signature}) => {
  // A key that is not a point on the curve cannot sign
  if (!isXOnlyPoint(public_key)) {
    return false;
  }

  // The sighash type byte that can follow the signature is not signed
  const schnorrSignature = signature.subarray(0, schnorrSignatureByteLength);

  const r = schnorrSignature.subarray(0, pointSize);
  const s = schnorrSignature.subarray(pointSize);

  // Numbers that are not below the curve order are not checked
  if (r.compare(order) >= 0 || s.compare(order) >= 0) {
    return false;
  }

  return verifySchnorr(hash, public_key, schnorrSignature);
};
