const derivationAsPath = require('./derivation_as_path');
const {fingerprintByteLength} = require('./constants');

/** Decode BIP32 Derivation Data

  {
    derivation: <BIP 32 Derivation Buffer Object>
    ecp: <ECPair Object>
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
module.exports = ({derivation, ecp, key}) => {
  let childKey;

  // Derive the public key from the public key bytes
  try {
    childKey = ecp.fromPublicKey(key);
  } catch (err) {
    throw new Error('InvalidBip32Key');
  }

  return {
    path: derivationAsPath({derivation}).path,
    fingerprint: derivation.slice(0, fingerprintByteLength).toString('hex'),
    public_key: childKey.publicKey.toString('hex'),
  };
};
