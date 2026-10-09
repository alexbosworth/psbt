const {compactIntAsNumber} = require('@alexbosworth/blockchain');

const isLeafVersion = require('./is_leaf_version');
const {maxTaprootTreeDepth} = require('./../psbts/constants');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const scriptLengthOffset = 2;

/** Parse out a Taproot script tree

  {
    encoded: <Encoded Taproot Script Tree Hex String>
  }

  @throws
  <Error>

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
  const branch = [];
  const tuples = [];

  // Read leaf script tuples until there are no more left
  while (!!tree.length) {
    const scriptSize = compactIntAsNumber({
      encoded: tree,
      start: scriptLengthOffset,
    });

    scriptLength = scriptSize.number;

    lengthCounterBytes = scriptSize.bytes;

    scriptStartIndex = scriptLengthOffset + lengthCounterBytes;

    scriptEndIndex = scriptStartIndex + scriptLength;

    // Every leaf must contain the full script that its length promises
    if (scriptEndIndex > tree.length) {
      throw new Error('ExpectedFullScriptForTaprootTreeLeaf');
    }

    const [depth, version] = tree;

    if (depth > maxTaprootTreeDepth) {
      throw new Error('UnexpectedDepthForTaprootTreeLeaf');
    }

    if (!isLeafVersion({version})) {
      throw new Error('InvalidLeafVersionForTaprootTreeLeaf');
    }

    // A leaf cannot be shallower than an unfinished deeper branch
    if (depth + 1 < branch.length) {
      throw new Error('ExpectedCompleteTaprootTree');
    }

    let level = depth;

    // Join the leaf with waiting siblings, moving up toward the root
    while (branch.length > level && !!branch[level]) {
      branch.pop();

      // Nodes cannot be joined above the root
      if (!level) {
        throw new Error('ExpectedCompleteTaprootTree');
      }

      level -= 1;
    }

    while (branch.length <= level) {
      branch.push(false);
    }

    branch[level] = true;

    tuples.push({
      depth,
      version,
      script: bufferAsHex(tree.subarray(scriptStartIndex, scriptEndIndex)),
    });

    tree = tree.subarray(scriptEndIndex);
  }

  // All of the leaves must join into exactly one root
  if (branch.length !== 1 || !branch[0]) {
    throw new Error('ExpectedCompleteTaprootTree');
  }

  return {tree: tuples};
};
