const varuint = require('varuint-bitcoin')

const derivationAsPath = require('./derivation_as_path');

const bufferAsHex = buffer => buffer.toString('hex');
const chunk = (a, l)=>[...Array(Math.ceil(a.length/l))].map(_=>a.splice(0,l));
const expectedTypeHexLength = 33 * 2;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const sizeFingerprint = 4;
const sizeHash = 32;
const slice = (buffer, start, size) => buffer.subarray(start, start + size);
const sumOf = arr => arr.reduce((sum, n) => sum + n, 0);
const typeAsPublicKey = type => type.substring(2);

/** Decode Taproot BIP32 values

  {
    type: <Key Type Hex String>
    value: <Key Value Hex String>
  }

  @throws
  <Error>

  @returns
  {
    fingerprint: <Master Key Fingerprint Hex String>
    leaf_hashes: [<Leaf Hash Hex String>]
    [path]: <BIP32 Derivation Path Child/Hardened Child/Index String>
    public_key: <X Only Internal or Leaf Public Key Hex String>
  }
*/
module.exports = ({type, value}) => {
  if (type.length !== expectedTypeHexLength) {
    throw new Error('ExpectedTypeNumberAndXOnlyPublicKeyInKeyType');
  }

  const cursor = [];
  const val = hexAsBuffer(value);

  const leafHashesCount = varuint.decode(val);

  // Finished reading the count of leaf hashes
  cursor.push(varuint.decode.bytes);

  const leafHashes = [...Array(leafHashesCount)].map((_, i) => {
    return bufferAsHex(slice(val, sumOf(cursor) + (i * sizeHash), sizeHash));
  });

  // Finished reading the leaf hashes
  cursor.push(leafHashesCount * sizeHash);

  const fingerprint = slice(val, sumOf(cursor), sizeFingerprint);

  const derivation = val.subarray(sumOf(cursor));

  return {
    fingerprint: bufferAsHex(fingerprint),
    leaf_hashes: leafHashes,
    path: derivationAsPath({derivation}).path,
    public_key: typeAsPublicKey(type),
  };
};
