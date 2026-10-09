const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const {tokensAsBuffer} = require('./../transactions');

const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Serialize a transaction output

  {
    script: <Output Script Hex String>
    tokens: <Output Tokens Number>
  }

  @returns
  <Serialized Output Buffer Object>
*/
module.exports = ({script, tokens}) => {
  const outputScript = hexAsBuffer(script);

  return Buffer.concat([
    tokensAsBuffer({tokens}),
    encode(outputScript.length),
    outputScript,
  ]);
};
