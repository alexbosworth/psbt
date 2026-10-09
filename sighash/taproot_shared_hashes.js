const {createHash} = require('node:crypto');

const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const {tokensAsBuffer} = require('./../transactions');

const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const sha256 = data => createHash('sha256').update(data).digest();

/** Calculate the transaction hashes that BIP 341 signature hashes share

  The amounts and scripts of the outputs that inputs spend are only hashed
  when the output that each input spends is known

  {
    parts: {
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
    }
    spent: [{
      [script]: <Spent Output Script Hex String>
      [tokens]: <Spent Output Tokens Number>
    }]
  }

  @returns
  {
    [amounts]: <Hash of All Spent Output Amounts Buffer Object>
    outputs: <Hash of All Outputs Buffer Object>
    prevouts: <Hash of All Spent Outpoints Buffer Object>
    [scripts]: <Hash of All Spent Output Scripts Buffer Object>
    sequences: <Hash of All Input Sequences Buffer Object>
  }
*/
module.exports = ({parts, spent}) => {
  const outputs = sha256(Buffer.concat(parts.outputs));
  const prevouts = sha256(Buffer.concat(parts.outpoints));
  const sequences = sha256(Buffer.concat(parts.sequences));

  // Exit early when the output that an input spends is not known
  if (!!spent.find(n => n.script === undefined)) {
    return {outputs, prevouts, sequences};
  }

  const amounts = spent.map(({tokens}) => tokensAsBuffer({tokens}));

  // Each spent output script is serialized with its length, as in an output
  const scripts = spent.map(({script}) => {
    const spentScript = hexAsBuffer(script);

    return Buffer.concat([encode(spentScript.length), spentScript]);
  });

  return {
    outputs,
    prevouts,
    sequences,
    amounts: sha256(Buffer.concat(amounts)),
    scripts: sha256(Buffer.concat(scripts)),
  };
};
