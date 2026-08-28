/** Encode a sighash type as an unsigned 32-bit little-endian buffer

  {
    sighash: <Sighash Type Number>
  }

  @returns
  <Sighash Type Buffer Object>
*/
module.exports = ({sighash}) => {
  const value = Buffer.alloc(4);

  value.writeUInt32LE(Number(sighash));

  return value;
};
