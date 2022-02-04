const {bip32KeyByteLength} = require('./constants');
const {bip32KeyLimit} = require('./constants');
const {fingerprintByteLength} = require('./constants');

const {floor} = Math;

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

  const path = derivation
    .reduce((sum, byte, i) => {
      const start = floor(i / bip32KeyByteLength);

      sum[start] = sum[start] || [];

      sum[start].push(byte);

      return sum;
    }, [])
    .map(n => Buffer.from(n))
    .slice([fingerprintByteLength].length)
    .reduce((sum, n) => {
      const i = n.readUInt32LE();

      const isHard = (i & bip32KeyLimit) !== 0;

      const adjustedIndex = isHard ? i - bip32KeyLimit : i;
      const marker = isHard ? `'` : '';

      return `${sum}/${adjustedIndex}${marker}`;
    },
    'm');

  return {
    path,
    fingerprint: derivation.slice(0, fingerprintByteLength).toString('hex'),
    public_key: childKey.publicKey.toString('hex'),
  };
};
