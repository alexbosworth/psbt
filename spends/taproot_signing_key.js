const {taprootTweakedKey} = require('./../signatures');

/** Get the private key that signs for the output key of a taproot input

  A signing key signs for an output key that is its own key, or that is its
  key tweaked as the internal key of an output without a script tree. The
  internal key of an input signs once it is tweaked with the merkle root of
  the input's script tree.

  {
    input: {
      [taproot_internal_key]: <Internal X Only Public Key Hex String>
      [taproot_root_hash]: <Script Tree Merkle Root Hex String>
    }
    keys: <Signing Keys By X Only Public Key Hex Map Object>
    output_key: <Taproot Output X Only Public Key Hex String>
    tweaked: <Keys Tweaked Without a Script Tree By Output Key Map Object>
  }

  @returns
  {
    [private_key]: <Private Key That Signs For the Output Key Buffer Object>
  }
*/
module.exports = ({input, keys, output_key, tweaked}) => {
  const key = keys.get(output_key) || tweaked.get(output_key);

  // A key that is the output key, or that tweaks to it, signs for the output
  if (!!key) {
    return {private_key: key.private_key};
  }

  const internalKey = keys.get(input.taproot_internal_key);

  // Exit early when there is no internal key to tweak with a merkle root
  if (!internalKey || input.taproot_root_hash === undefined) {
    return {};
  }

  // The internal key is tweaked with the merkle root of the script tree
  const scriptTreeKey = taprootTweakedKey({
    merkle_root: input.taproot_root_hash,
    private_key: internalKey.private_key,
  });

  // Exit early when the tweaked internal key is not the output key
  if (scriptTreeKey.output_key !== output_key) {
    return {};
  }

  return {private_key: scriptTreeKey.private_key};
};
