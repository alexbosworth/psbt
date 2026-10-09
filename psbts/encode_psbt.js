const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const decodePsbt = require('./decode_psbt');
const {readCompactSize} = require('./../transactions');
const {terminatorByte} = require('./constants');
const types = require('./types');

const asHex = bytes => Buffer.from(bytes).toString('hex');
const encode = number => numberAsCompactInt({number}).encoded;
const globalSeparator = Buffer.from(types.global.separator, 'hex');
const {isArray} = Array;
const isBytes = n => n instanceof Uint8Array;
const magicBytes = Buffer.from(types.global.magic);
const terminator = Buffer.from(terminatorByte, 'hex');

/** Encode a Partially Signed Bitcoin Transaction

  Every key starts with a complete, minimally encoded type number, and a key
  can only be used once within a section. A separator ends a section. The
  pairs must encode a valid PSBT.

  {
    pairs: [{
      [separator]: <Is Separator Bool>
      [type]: <Type Buffer Object>
      [value]: <Value Buffer Object>
    }]
  }

  @throws
  <Failed To Encode Error>

  @returns
  {
    psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
  }
*/
module.exports = ({pairs}) => {
  if (!isArray(pairs)) {
    throw new Error('ExpectedKeyValuePairsToEncode');
  }

  // Keys already used in the current section
  let sectionKeys = new Set();

  const encodedPairs = Buffer.concat(pairs.map(pair => {
    // Every entry is either a separator or a key and a value
    if (!pair || typeof pair !== 'object') {
      throw new Error('ExpectedKeyAndValueForPsbtPair');
    }

    const {separator, type, value} = pair;

    const hasKeyOrValue = type !== undefined || value !== undefined;

    // A separator ends a section, so it cannot also carry a key or value
    if (!!separator && hasKeyOrValue) {
      throw new Error('UnexpectedKeyOrValueForSeparator');
    }

    // The next section starts with no keys used
    if (!!separator) {
      sectionKeys = new Set();

      return terminator;
    }

    if (type === undefined || value === undefined) {
      throw new Error('ExpectedKeyAndValueForPsbtPair');
    }

    // Keys and values are bytes, and a key cannot be empty
    if (!isBytes(type)) {
      throw new Error('ExpectedBytesForPsbtKey');
    }

    if (!isBytes(value)) {
      throw new Error('ExpectedBytesForPsbtValue');
    }

    // An empty key would be read as a separator that ends the section
    if (!type.length) {
      throw new Error('ExpectedNonEmptyKeyForPsbtField');
    }

    // A key starts with its type, a complete and minimally encoded number
    try {
      readCompactSize({encoded: type});
    } catch (err) {
      throw new Error('InvalidPsbtKeyTypeEncoding');
    }

    const key = asHex(type);

    // Keys of the same type are allowed, but not the same key twice
    if (sectionKeys.has(key)) {
      throw new Error('UnexpectedDuplicateKeyInPsbtSection');
    }

    sectionKeys.add(key);

    return Buffer.concat([
      encode(type.length),
      type,
      encode(value.length),
      value,
    ]);
  }));

  const psbt = Buffer.concat([
    magicBytes,
    globalSeparator,
    encodedPairs,
  ]).toString('hex');

  // The pairs must encode a valid PSBT
  decodePsbt({psbt});

  return {psbt};
};
