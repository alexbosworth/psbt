const {bip32KeyByteLength} = require('./constants');
const {bip32KeyLimit} = require('./constants');
const {fingerprintByteLength} = require('./constants');

const {floor} = Math;

/** Map derivation bytes to a bip32 path

  {
    derivation: <Derivation Buffer Object>
  }

  @returns
  {
    [path]: <Path String>
  }
*/
module.exports = ({derivation}) => {
  if (derivation.length === fingerprintByteLength) {
    return {};
  }

  const path = derivation
    .reduce((sum, byte, i) => {
      const start = floor(i / bip32KeyByteLength);

      sum[start] = sum[start] || [];

      sum[start].push(byte);

      return sum;
    }, [])
    .map(n => Buffer.from(n))
    .slice([fingerprintByteLength].length)
    .reduce((sum, n) => {
      const i = n.readUInt32LE();

      const isHard = (i & bip32KeyLimit) !== 0;

      const adjustedIndex = isHard ? i - bip32KeyLimit : i;
      const marker = isHard ? `'` : '';

      return `${sum}/${adjustedIndex}${marker}`;
    },
    'm');

  return {path};
};
