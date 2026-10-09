const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const bip32Path = require('./bip32_path');

const bufferAsHex = buffer => buffer.toString('hex');
const encode = number => numberAsCompactInt({number}).encoded;
const encodeList = n => encode(n.length).toString('hex') + n.join('');
const isLegacy = n => [66, 130].includes(n.public_key.length);
const isTaproot = n => n.public_key.length === 64;

/** Encode BIP32 derivations as values

  {
    bip32_derivations: [{
      fingerprint: <Public Key Fingerprint Hex String>
      [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
      [path]: <BIP 32 Child / Hardened Child / Index Derivation Path String>
      public_key: <Public Key Hex String>
    }]
  }

  @returns
  {
    legacy: [{
      key: <Legacy Public Key Hex String>
      value: <Legacy BIP 32 Derivation Hex String>
    }]
    taproot: [{
      key: <Taproot Public Key Hex String>
      value: <Taproot BIP 32 Derivation Hex String>
    }]
  }
*/
module.exports = args => {
  const legacy = args.bip32_derivations.filter(isLegacy).map(derivation => {
    const {path} = derivation;

    return {
      key: derivation.public_key,
      value: derivation.fingerprint + bufferAsHex(bip32Path({path})),
    };
  });

  const taproot = args.bip32_derivations.filter(isTaproot).map(derivation => {
    // Leaf hashes that are not given are an empty list of leaf hashes
    const leafs = encodeList(derivation.leaf_hashes || []);
    const {path} = derivation;

    return {
      key: derivation.public_key,
      value: leafs + derivation.fingerprint + bufferAsHex(bip32Path({path})),
    };
  });

  return {legacy, taproot};
};
