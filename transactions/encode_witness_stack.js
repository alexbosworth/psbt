const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const encode = number => numberAsCompactInt({number}).encoded;

/** Encode a script witness stack

  {
    elements: [<Stack Element Buffer Object>]
  }

  @returns
  {
    witness: <Encoded Script Witness Buffer Object>
  }
*/
module.exports = ({elements}) => {
  const items = elements.map(n => Buffer.concat([encode(n.length), n]));

  return {witness: Buffer.concat([encode(elements.length), ...items])};
};
