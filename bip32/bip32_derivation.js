const {bip32KeyByteLength} = require('./constants');
const {bip32KeyLimit} = require('./constants');
const {ECPair} = require('./../tokens');
const {fingerprintByteLength} = require('./constants');

/** Decode BIP32 Derivation Data

  {
    derivation: <BIP 32 Derivation Buffer Object>
    key: <Public Key Buffer Object>
  }

  @throws
  <InvalidBip32Key Error>

  @returns
  {
    fingerprint: <BIP32 Fingerprint Hex String>
    path: <BIP32 Derivation Path Child/Hardened Child/Index String>
    public_key: <Public Key Hex String>
  }
*/
module.exports = ({derivation, key}) => {
  let childKey;

  // Derive the public key from the public key bytes
  try {
    childKey = ECPair.fromPublicKey(key);
  } catch (err) {
    throw new Error('InvalidBip32Key');
  }

  const child = derivation.readUInt32LE(fingerprintByteLength) - bip32KeyLimit;

  const hardChildOffset = fingerprintByteLength + bip32KeyByteLength;

  const hardChild = derivation.readUInt32LE(hardChildOffset) - bip32KeyLimit;

  const childIndexOffset = hardChildOffset + bip32KeyByteLength;

  const childIndex = derivation.readUInt32LE(childIndexOffset) - bip32KeyLimit;

  return {
    fingerprint: derivation.slice(0, fingerprintByteLength).toString('hex'),
    path: `m/${child}'/${hardChild}'/${childIndex}'`,
    public_key: childKey.publicKey.toString('hex'),
  };
};

