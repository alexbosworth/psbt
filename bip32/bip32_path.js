const BN = require('bn.js');

const {bip32KeyByteLength} = require('./constants');
const {bip32KeyLimit} = require('./constants');
const {bip32PathSeparator} = require('./constants');
const {decBase} = require('./constants');
const {endianness} = require('./constants');
const {hardenedMarker} = require('./constants');

const {concat} = Buffer;

/** Encode a BIP32 path

  {
    path: <BIP 32 Path String>
  }

  @returns
  <BIP 32 Path Buffer Object>
*/
module.exports = ({path}) => {
  const byteLength = bip32KeyByteLength;
  const [, child, childHardened, childIndex] = path.split(bip32PathSeparator);

  return concat([child, childHardened, childIndex].map(n => {
    const len = hardenedMarker.length;

    const path = n.slice(-len) === hardenedMarker ? n.slice(0, -len) : n;

    const value = parseInt(path, decBase) + bip32KeyLimit;

    return new BN(value, decBase).toArrayLike(Buffer, endianness, byteLength);
  }));
};

