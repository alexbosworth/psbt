const {compactIntAsNumber} = require('@alexbosworth/blockchain');

const types = require('./types');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const magicByteLength = Buffer.from(types.global.magic).length + 1;

/** Split an encoded PSBT into the key-value pairs of each of its sections

  The PSBT is expected to have been validated

  {
    psbt: <Hex Encoded PSBT String>
  }

  @throws
  <ExpectedMoreBytesForPsbtKeyOrValue Error>

  @returns
  {
    sections: [[{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]]
  }
*/
module.exports = ({psbt}) => {
  const buffer = hexAsBuffer(psbt);
  const sections = [[]];
  let offset = magicByteLength;

  // Read a length-prefixed key or value
  const read = () => {
    const {bytes, number} = compactIntAsNumber({
      encoded: buffer,
      start: offset,
    });

    offset += bytes;

    if (number > buffer.length - offset) {
      throw new Error('ExpectedMoreBytesForPsbtKeyOrValue');
    }

    offset += number;

    return buffer.subarray(offset - number, offset);
  };

  while (offset < buffer.length) {
    const type = read();

    // An empty key is a separator that ends the section and starts the next
    if (!type.length) {
      sections.push([]);

      continue;
    }

    sections.at(-1).push({type, value: read()});
  }

  // The final separator ends the final section
  sections.pop();

  return {sections};
};
