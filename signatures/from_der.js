const {pointSize} = require('./constants');

const {alloc} = Buffer;
const signPadding = 0x00;

/** Get from DER

  {
    x: <Buffer Object>
  }

  @throws
  <UnexpectedOversizedNumberInSignature Error>

  @returns
  <Buffer Object>
*/
module.exports = ({x}) => {
  // A leading zero byte is sign padding, not part of the number
  const number = x[0] === signPadding ? x.subarray(1) : x;

  // A number that does not fit would lose bytes when it is converted
  if (number.length > pointSize) {
    throw new Error('UnexpectedOversizedNumberInSignature');
  }

  const buffer = alloc(pointSize, 0);

  number.copy(buffer, pointSize - number.length);

  return buffer;
};
