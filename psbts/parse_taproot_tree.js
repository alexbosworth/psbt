const {compactIntAsNumber} = require('@alexbosworth/blockchain');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const scriptLengthOffset = 2;
const versionOffset = 1;

/** Parse out a Taproot script tree

  {
    encoded: <Encoded Taproot Script Tree Hex String>
  }

  @returns
  {
    tree: [{
      depth: <Tree Depth Number>
      script: <Leaf Script Hex String>
      version: <Leaf Script Version Number>
    }]
  }
*/
module.exports = ({encoded}) => {
  let lengthCounterBytes;
  let scriptEndIndex;
  let scriptLength;
  let scriptStartIndex;
  let tree = hexAsBuffer(encoded);
  const tuples = [];

  // Read leaf script tuples until there are no more left
  while (!!tree.length) {
    const length = compactIntAsNumber({
      encoded: tree,
      start: scriptLengthOffset,
    });

    scriptLength = length.number;

    lengthCounterBytes = length.bytes;

    scriptStartIndex = scriptLengthOffset + lengthCounterBytes;

    scriptEndIndex = scriptStartIndex + scriptLength;

    tuples.push({
      depth: tree.readUInt8(),
      version: tree.readUInt8(versionOffset),
      script: bufferAsHex(tree.subarray(scriptStartIndex, scriptEndIndex)),
    });

    tree = tree.subarray(scriptEndIndex);
  }

  return {tree: tuples};
};
