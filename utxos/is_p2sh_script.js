const {OP_EQUAL} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');

const {p2shHashByteLength} = require('./constants');

const p2shScriptByteLength = 23;

/** Determine if a script is exactly a P2SH output script

  {
    script: <Script Buffer Object>
  }

  @returns
  <Is P2SH Output Script Bool>
*/
module.exports = ({script}) => {
  if (script.length !== p2shScriptByteLength) {
    return false;
  }

  if (script[0] !== OP_HASH160 || script[1] !== p2shHashByteLength) {
    return false;
  }

  return script.at(-1) === OP_EQUAL;
};
