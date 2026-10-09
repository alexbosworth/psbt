const derivationAsPath = require('./derivation_as_path');
const {fingerprintByteLength} = require('./constants');

/** Decode BIP32 Derivation Data

  The public key is expected to already be checked as a valid public key

  {
    derivation: <BIP 32 Derivation Buffer Object>
    key: <Public Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    fingerprint: <BIP32 Fingerprint Hex String>
    [path]: <BIP32 Derivation Path Child/Hardened Child/Index String>
    public_key: <Public Key Hex String>
  }
*/
module.exports = ({derivation, key}) => {
  return {
    path: derivationAsPath({derivation}).path,
    fingerprint: derivation.slice(0, fingerprintByteLength).toString('hex'),
    public_key: key.toString('hex'),
  };
};
