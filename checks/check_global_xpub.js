const {isPoint} = require('tiny-secp256k1');

const {bip32KeyByteLength} = require('./../bip32/constants');
const derivationAsPath = require('./../bip32/derivation_as_path');
const {fingerprintByteLength} = require('./../bip32/constants');

const childIndexOffset = 9;
const depthOffset = 4;
const parentFingerprintOffset = 5;
const publicKeyOffset = 45;
const xpubByteLength = 78;

/** Check a global extended public key and its key origin

  {
    value: <Key Origin Buffer Object>
    xpub: <Serialized Extended Public Key Buffer Object>
  }

  @throws
  <Error>
*/
module.exports = ({value, xpub}) => {
  // An extended public key is always serialized as 78 bytes
  if (xpub.length !== xpubByteLength) {
    throw new Error('ExpectedSerializedExtendedPublicKeyForGlobalXpub');
  }

  // It ends with a valid compressed public key
  if (!isPoint(xpub.subarray(publicKeyOffset))) {
    throw new Error('InvalidPublicKeyForGlobalXpub');
  }

  const depth = xpub[depthOffset];

  const index = xpub.readUInt32BE(childIndexOffset);
  const parentFingerprint = xpub.readUInt32BE(parentFingerprintOffset);

  // A master key has no parent, so its parent fingerprint and index are zero
  if (!depth && (!!parentFingerprint || !!index)) {
    throw new Error('UnexpectedParentForMasterGlobalXpub');
  }

  // The key origin is a master fingerprint followed by whole path elements
  derivationAsPath({derivation: value});

  const pathByteLength = value.length - fingerprintByteLength;

  // There is a path element for every level of depth of the key
  if (pathByteLength / bip32KeyByteLength !== depth) {
    throw new Error('UnexpectedPathLengthForGlobalXpubDepth');
  }

  return;
};
