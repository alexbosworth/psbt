const {taprootAnnexTag} = require('./../psbts/constants');
const {taprootLeafVersionMask} = require('./../psbts/constants');

/** Determine if a number is a valid taproot leaf version

  {
    version: <Leaf Version Number>
  }

  @returns
  <Is Valid Leaf Version Bool>
*/
module.exports = ({version}) => {
  // The lowest bit of a control block byte is the parity, not the version
  if ((version & taprootLeafVersionMask) !== version) {
    return false;
  }

  // The annex tag would make the witness ambiguous
  return version !== taprootAnnexTag;
};
