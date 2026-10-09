const {bip32KeyLimit} = require('./constants');
const {bip32PathSeparator} = require('./constants');
const {decBase} = require('./constants');

const childPattern = /^[0-9]+'?$/;
const masterKey = 'm';

/** Determine if a BIP 32 path is complete and has valid child indexes

  {
    path: <BIP 32 Path String>
  }

  @returns
  <Is Valid BIP 32 Path Bool>
*/
module.exports = ({path}) => {
  // Exit early when the path is not a string
  if (typeof path !== 'string') {
    return false;
  }

  const [master, ...children] = path.split(bip32PathSeparator);

  // A path starts at the master key
  if (master !== masterKey) {
    return false;
  }

  // Each child is an index that can be hardened, checked one by one because
  // a single pattern repeated over a long path can overflow the stack
  if (children.find(n => !childPattern.test(n)) !== undefined) {
    return false;
  }

  // Each child index must be below the hardened index offset
  const tooHigh = children.find(n => parseInt(n, decBase) >= bip32KeyLimit);

  return tooHigh === undefined;
};
