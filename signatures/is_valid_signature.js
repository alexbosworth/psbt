const {verify} = require('tiny-secp256k1');

const {curveOrder} = require('./constants');
const decodeSignature = require('./decode_signature');
const {pointSize} = require('./constants');

const order = Buffer.from(curveOrder, 'hex');

/** Determine if an encoded ECDSA signature is a valid signature of a hash

  A valid signature has the low s value that relay policy requires

  {
    hash: <Signed Hash Buffer Object>
    public_key: <Public Key Buffer Object>
    signature: <DER Encoded Signature With Sighash Type Buffer Object>
  }

  @throws
  <Error>

  @returns
  <Signature Is Valid Bool>
*/
module.exports = ({hash, public_key, signature}) => {
  const decoded = decodeSignature({signature});

  const r = decoded.signature.subarray(0, pointSize);
  const s = decoded.signature.subarray(pointSize);

  // Numbers that are not below the curve order cannot be verified
  if (r.compare(order) >= 0 || s.compare(order) >= 0) {
    return false;
  }

  // The strict check also requires a low s value
  return verify(hash, public_key, decoded.signature, true);
};
