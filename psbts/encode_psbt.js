const varuint = require('varuint-bitcoin');

const {terminatorByte} = require('./constants');
const types = require('./types');

const globalSeparator = Buffer.from(types.global.separator, 'hex');
const magicBytes = Buffer.from(types.global.magic);
const terminator = Buffer.from(terminatorByte, 'hex');

/** Encode a Partially Signed Bitcoin Transaction

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
  if (!Array.isArray(pairs)) {
    throw new Error('ExpectedKeyValuePairsToEncode');
  }

  const components = [magicBytes, globalSeparator];

  let lastType = null;

  const encodedPairs = Buffer.concat(pairs.map(({separator, type, value}) => {
    if ((!type || !value) && !separator) {
      throw new Error('ExpectedSeparator');
    }

    if (!type) {
      return terminator;
    }

    return Buffer.concat([
      varuint.encode(type.length),
      type,
      varuint.encode(value.length),
      value,
    ]);
  }));

  const psbt = Buffer.concat([
    magicBytes,
    globalSeparator,
    encodedPairs,
  ]);

  return {psbt: psbt.toString('hex')};
};
