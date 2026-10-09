const {checkedKeys} = require('./../script');
const {p2pkhHashByteLength} = require('./../utxos/constants');
const {witnessProgram} = require('./../utxos');

const bufferAsHex = buffer => buffer.toString('hex');
const versionZero = 0;

/** Collect the BIP 32 derivations of keys that scripts check signatures with

  Keys are found where scripts check signatures with them, and in version 0
  witness programs of a public key hash. A key that a script only has as data
  is not found.

  {
    derivations: <Derivations By Public Key and Public Key Hash Hex Map Object>
    scripts: [<Script Buffer Object>]
  }

  @returns
  {
    derivations: [{
      fingerprint: <Public Key Fingerprint Hex String>
      [path]: <BIP 32 Derivation Path String>
      public_key: <Public Key Hex String>
    }]
  }
*/
module.exports = ({derivations, scripts}) => {
  const found = new Map();

  // A key is found when a script checks a signature with that key
  const addKey = publicKey => {
    const key = bufferAsHex(publicKey);

    const derivation = derivations.get(key);

    if (!!derivation && derivation.public_key === key) {
      found.set(key, derivation);
    }

    return;
  };

  // A key is found when a script checks a signature with a key of that hash
  const addKeyHash = hash => {
    const derivation = derivations.get(bufferAsHex(hash));

    if (!!derivation) {
      found.set(derivation.public_key, derivation);
    }

    return;
  };

  scripts.forEach(script => {
    const checked = checkedKeys({script: bufferAsHex(script)});
    const {program, version} = witnessProgram({script});

    const isVersionZero = version === versionZero;

    // A version 0 program of a key hash pays to the key with that hash
    if (isVersionZero && program.length === p2pkhHashByteLength) {
      addKeyHash(program);
    }

    checked.hashes.forEach(hash => addKeyHash(hash));
    checked.keys.forEach(key => addKey(key));

    return;
  });

  return {derivations: [...found.values()]};
};
