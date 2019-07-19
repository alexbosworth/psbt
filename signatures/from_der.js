const {pointSize} = require('./constants');

const {alloc} = Buffer;
const {max} = Math;

/** Get from DER

  {
    x: <Buffer Object>
  }

  @returns
  <Buffer Object>
*/
module.exports = ({x}) => {
  if (x[0] === 0x00) {
    x = x.slice(1);
  }

  const bstart = max(0, pointSize - x.length);
  const buffer = alloc(pointSize, 0);

  x.copy(buffer, bstart);

  return buffer;
};
