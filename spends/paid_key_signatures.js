const hash160 = require('./hash160');
const {scriptTemplate} = require('./../script');

const bufferAsHex = buffer => buffer.toString('hex');

/** Select the signatures of the keys that a script pays to

  Signatures of other keys cannot satisfy the script, so they are left out

  {
    [script]: <Script Hex String>
    signatures: [{
      public_key: <Public Key Buffer Object>
      signature: <Signature Buffer Object>
    }]
  }

  @returns
  {
    signatures: [{
      public_key: <Public Key Buffer Object>
      signature: <Signature Buffer Object>
    }]
  }
*/
module.exports = ({script, signatures}) => {
  // Exit early when there is no script for signatures to satisfy
  if (script === undefined) {
    return {signatures: []};
  }

  const {hash, key, keys} = scriptTemplate({script});

  // A script that pays to a public key takes a signature of that key
  if (!!key) {
    return {signatures: signatures.filter(n => n.public_key.equals(key))};
  }

  // A script that pays to a key hash takes a signature of a key with the hash
  if (!!hash) {
    return {
      signatures: signatures.filter(n => {
        const keyHash = hash160({data: n.public_key});

        return keyHash.equals(hash);
      }),
    };
  }

  const paidKeys = new Set((keys || []).map(bufferAsHex));

  const isPaid = n => paidKeys.has(bufferAsHex(n.public_key));

  // A multisig takes signatures of its keys, other scripts take none
  return {signatures: signatures.filter(isPaid)};
};
