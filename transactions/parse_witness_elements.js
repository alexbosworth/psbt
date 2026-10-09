const {compactIntAsNumber} = require('@alexbosworth/blockchain');

/** Parse serialized witness stack elements

  {
    encoded: <Serialized Witness Stack Elements Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    elements: [<Witness Stack Element Buffer Object>]
  }
*/
module.exports = ({encoded}) => {
  const elements = [];
  let offset = 0;

  while (offset < encoded.length) {
    const size = compactIntAsNumber({encoded, start: offset});

    offset += size.bytes;

    // An element must contain all of the bytes that its length promises
    if (size.number > encoded.length - offset) {
      throw new Error('ExpectedFullWitnessElement');
    }

    elements.push(encoded.subarray(offset, offset + size.number));

    offset += size.number;
  }

  return {elements};
};
