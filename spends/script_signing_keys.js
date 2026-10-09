const hash160 = require('./hash160');
const {scriptTemplate} = require('./../script');

const bufferAsHex = buffer => buffer.toString('hex');
const compressedPublicKeyByteLength = 33;

/** Find the signing keys that a script checks signatures with

  Keys are found for scripts that pay to a public key, to a public key hash,
  or to a multisig of public keys. Other scripts have no signing keys.

  Witness scripts are only signed with compressed public keys.

  {
    is_witness: <Script Is Signed as a Witness Script Bool>
    keys: <Signing Keys By Public Key and Public Key Hash Hex Map Object>
    script: <Script Code Hex String>
  }

  @returns
  {
    keys: [{
      private_key: <Private Key Buffer Object>
      public_key: <Public Key Buffer Object>
    }]
  }
*/
module.exports = ({is_witness, keys, script}) => {
  const found = new Set();
  const template = scriptTemplate({script});

  // A key signs when the script checks a signature with its public key
  const addKey = publicKey => {
    const key = keys.get(bufferAsHex(publicKey));

    if (!!key && key.public_key.equals(publicKey)) {
      found.add(key);
    }

    return;
  };

  if (!!template.key) {
    addKey(template.key);
  }

  // A key signs when the script checks a signature with its public key hash
  if (!!template.hash && keys.has(bufferAsHex(template.hash))) {
    const key = keys.get(bufferAsHex(template.hash));

    const keyHash = hash160({data: key.public_key});

    if (keyHash.equals(template.hash)) {
      found.add(key);
    }
  }

  (template.keys || []).forEach(publicKey => addKey(publicKey));

  const signingKeys = [...found];

  // Exit early when uncompressed keys can sign a legacy script
  if (!is_witness) {
    return {keys: signingKeys};
  }

  // Witness scripts are only signed with compressed public keys
  return {
    keys: signingKeys.filter(key => {
      return key.public_key.length === compressedPublicKeyByteLength;
    }),
  };
};
