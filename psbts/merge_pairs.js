const bufferAsHex = buffer => buffer.toString('hex');
const notFound = -1;
const typeOfKey = key => key.subarray(0, 1).toString('hex');

/** Set key-value pairs over the pairs of a section of a PSBT

  {
    order: [<Standard Order of Key Type Hex String>]
    pairs: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
    section: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
  }

  @returns
  {
    section: [{
      type: <Key Buffer Object>
      value: <Value Buffer Object>
    }]
  }
*/
module.exports = args => {
  const entries = new Map();
  const section = args.section.map(pair => ({pair}));

  // Kinds that are not in the standard order come after all of the others
  const rankOf = key => {
    const rank = args.order.indexOf(typeOfKey(key));

    return rank === notFound ? args.order.length : rank;
  };

  section.forEach(entry => entries.set(bufferAsHex(entry.pair.type), entry));

  args.pairs.forEach(pair => {
    const entry = entries.get(bufferAsHex(pair.type));

    // A key that is already present gets the new value
    if (!!entry) {
      entry.pair = pair;

      return;
    }

    const added = {pair};

    entries.set(bufferAsHex(pair.type), added);

    return section.push(added);
  });

  return {
    section: section
      .map(({pair}) => ({pair, rank: rankOf(pair.type)}))
      .sort((a, b) => a.rank - b.rank)
      .map(({pair}) => pair),
  };
};
