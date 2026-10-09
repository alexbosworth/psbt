const {createHash} = require('node:crypto');

const types = require('./../psbts/types');

/** Check that a hash preimage matches the hash that it is keyed by

  {
    hash: <Hash Buffer Object>
    preimage: <Preimage Buffer Object>
    type: <Preimage Type Hex String>
  }

  @throws
  <UnexpectedHashLengthForPreimage Error>
  <ExpectedPreimageMatchingHash Error>
*/
module.exports = ({hash, preimage, type}) => {
  // Hashing the preimage with each hash function of its type in turn
  const expected = types.preimages[type].reduce((data, algorithm) => {
    return createHash(algorithm).update(data).digest();
  },
  preimage);

  // The key is the type followed by exactly one hash of the expected size
  if (hash.length !== expected.length) {
    throw new Error('UnexpectedHashLengthForPreimage');
  }

  // Hashing the preimage must produce the hash in the key
  if (!expected.equals(hash)) {
    throw new Error('ExpectedPreimageMatchingHash');
  }

  return;
};
