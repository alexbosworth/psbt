/** Encode a number as an unsigned 32-bit little-endian buffer

  {
    number: <Number To Encode Number>
  }

  @returns
  <Encoded Number Buffer Object>
*/
module.exports = ({number}) => {
  const value = Buffer.alloc(4);

  value.writeUInt32LE(number);

  return value;
};
