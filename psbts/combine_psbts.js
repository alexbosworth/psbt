const {checkInputSighashTypes} = require('./../checks');
const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
const psbtSections = require('./psbt_sections');
const types = require('./types');

const bufferAsHex = buffer => buffer.toString('hex');
const {isArray} = Array;
const notFound = -1;
const typeOfKey = key => key.subarray(0, 1).toString('hex');

/** Combine multiple PSBTs

  Values that describe a spend, such as UTXOs, scripts, key origins, and
  sighash types, must match across PSBTs. For other values that differ, such
  as signatures and final scripts, the earliest PSBT's value is used.

  Signatures must use the sighash type of their input when it has one. A 64
  byte taproot signature uses the default sighash type.

  {
    psbts: [<BIP 174 Encoded PSBT Hex String>]
  }

  @throws
  <Combine PSBT Error>

  @returns
  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }
*/
module.exports = ({psbts}) => {
  if (!isArray(psbts) || !psbts.length) {
    throw new Error('ExpectedPsbtsToCombine');
  }

  let kinds;
  const pairs = [];
  let sections;
  let transaction;

  // Decode and combine one PSBT at a time so a mismatch stops early
  psbts.forEach(psbt => {
    const decoded = decodePsbt({psbt});

    // Transactions must be unique for all combined psbts
    if (!!transaction && transaction !== decoded.unsigned_transaction) {
      throw new Error('ExpectedUniqueTransaction');
    }

    const {sections: next} = psbtSections({psbt});

    transaction = decoded.unsigned_transaction;

    // The kind of each section, the global section then inputs then outputs
    kinds = kinds || [
      'global',
      ...decoded.inputs.map(() => 'input'),
      ...decoded.outputs.map(() => 'output'),
    ];

    // Each section keeps one lookup table of its keys for the combination
    sections = sections || next.map(() => ({pairs: [], values: new Map()}));

    return next.forEach((section, i) => {
      const combined = sections[i];
      const mustMatch = types.must_match[kinds[i]];

      return section.forEach(pair => {
        const key = bufferAsHex(pair.type);

        // A key that is new to the section is added
        if (!combined.values.has(key)) {
          combined.values.set(key, pair.value);

          return combined.pairs.push(pair);
        }

        const isSame = combined.values.get(key).equals(pair.value);

        // Values describing the spend must match, others keep the earliest
        if (!isSame && mustMatch.includes(typeOfKey(pair.type))) {
          throw new Error('ExpectedMatchingValuesToCombinePsbts');
        }

        return;
      });
    });
  });

  // Signatures must use the sighash type of their input when it has one
  sections.forEach((section, i) => {
    // Exit early when the section is not an input
    if (kinds[i] !== 'input') {
      return;
    }

    return checkInputSighashTypes({pairs: section.pairs});
  });

  // Each section is put into the standard order of its kinds once, at the end
  sections.forEach((section, i) => {
    const order = types.order[kinds[i]];

    // Kinds that are not in the standard order come after all of the others
    const ranked = section.pairs.map(pair => {
      const rank = order.indexOf(typeOfKey(pair.type));

      return {pair, rank: rank === notFound ? order.length : rank};
    });

    // Pairs of the same kind keep the order that they were added in
    ranked.sort((a, b) => a.rank - b.rank).forEach(n => pairs.push(n.pair));

    return pairs.push({separator: true});
  });

  // The combined pairs must also form a valid PSBT together
  const {psbt} = encodePsbt({pairs});

  return {psbt};
};
