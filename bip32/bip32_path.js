const {bip32KeyByteLength} = require('./constants');
const {bip32KeyLimit} = require('./constants');
const {bip32PathSeparator} = require('./constants');
const {decBase} = require('./constants');
const {fingerprintByteLength} = require('./constants');
const {hardenedMarker} = require('./constants');

const {concat} = Buffer;
const fingerprintLen = [fingerprintByteLength].length;

/** Encode a BIP32 path

  {
    path: <BIP 32 Path String>
  }

  @returns
  <BIP 32 Path Buffer Object>
*/
module.exports = ({path}) => {
  const byteLength = bip32KeyByteLength;

  return concat(path.split(bip32PathSeparator).slice(fingerprintLen).map(n => {
    const len = hardenedMarker.length;

    const isHard = n.slice(-len) === hardenedMarker;

    const path = isHard ? n.slice(0, -len) : n;

    const value = parseInt(path, decBase) + (isHard ? bip32KeyLimit : 0);

    // The child index is encoded as an unsigned 32-bit little-endian number
    const child = Buffer.alloc(byteLength);

    child.writeUInt32LE(value);

    return child;
  }));
};
