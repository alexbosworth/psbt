/** Encode a number as a minimal big-endian buffer

  {
    number: <Number To Encode Number>
  }

  @returns
  <Encoded Number Buffer Object>
*/
module.exports = ({number}) => {
  const hex = number.toString(16);

  return Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
};
