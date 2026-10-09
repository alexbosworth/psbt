const {createHash} = require('node:crypto');

const {pointFromScalar} = require('tiny-secp256k1');
const {privateAdd} = require('tiny-secp256k1');
const {privateNegate} = require('tiny-secp256k1');
const {xOnlyPointFromScalar} = require('tiny-secp256k1');

const bufferAsHex = bytes => Buffer.from(bytes).toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const isOddKey = publicKey => publicKey[0] === 3;
const noMerkleRoot = Buffer.alloc(0);
const sha256 = data => createHash('sha256').update(data).digest();
const tag = Buffer.from('TapTweak');

/** Tweak an internal private key to get the private key of its taproot output

  The tweak commits to the internal key and to the merkle root of the output's
  script tree, or to no merkle root when the output has no script tree. An
  internal key with an odd public key is negated before it is tweaked.

  {
    [merkle_root]: <Script Tree Merkle Root Hex String>
    private_key: <Internal Private Key Buffer Object>
  }

  @returns
  {
    output_key: <Taproot Output X Only Public Key Hex String>
    private_key: <Tweaked Private Key Buffer Object>
  }
*/
module.exports = ({merkle_root, private_key}) => {
  const hasRoot = merkle_root !== undefined;
  const publicKey = pointFromScalar(private_key, true);
  const tagHash = sha256(tag);

  const internalKey = publicKey.subarray(1);
  const root = hasRoot ? hexAsBuffer(merkle_root) : noMerkleRoot;

  // The tweak is a hash tagged as a taproot tweak of the key and the root
  const tweak = sha256(Buffer.concat([tagHash, tagHash, internalKey, root]));

  // The internal key is used as the key with the even public key
  const key = isOddKey(publicKey) ? privateNegate(private_key) : private_key;

  const tweaked = privateAdd(key, tweak);

  return {
    output_key: bufferAsHex(xOnlyPointFromScalar(tweaked)),
    private_key: Buffer.from(tweaked),
  };
};
