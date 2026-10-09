const hash256 = require('./hash256');

/** Calculate the transaction hashes that BIP 143 signature hashes share

  {
    parts: {
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
    }
  }

  @returns
  {
    outputs: <Hash of All Outputs Buffer Object>
    prevouts: <Hash of All Spent Outpoints Buffer Object>
    sequences: <Hash of All Input Sequences Buffer Object>
  }
*/
module.exports = ({parts}) => {
  return {
    outputs: hash256({data: Buffer.concat(parts.outputs)}),
    prevouts: hash256({data: Buffer.concat(parts.outpoints)}),
    sequences: hash256({data: Buffer.concat(parts.sequences)}),
  };
};
