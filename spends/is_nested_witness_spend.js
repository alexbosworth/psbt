const {p2shOutputScript} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const hash160 = require('./hash160');
const {isWitnessProgram} = require('./../utxos');
const {pushData} = require('./../script');

const asElements = script => scriptAsScriptElements({script}).elements || [];
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isBuffer} = Buffer;

/** Determine if a scriptSig spends a P2SH output with a nested witness program

  {
    script: <ScriptSig Hex String>
    spent: <Spent Output Script Buffer Object>
  }

  @returns
  <Spends a Witness Program Nested in a P2SH Output Bool>
*/
module.exports = ({script, spent}) => {
  const [redeem] = asElements(script);

  // The scriptSig pushes a witness program
  if (!isBuffer(redeem) || !isWitnessProgram({script: redeem})) {
    return false;
  }

  // The push of the witness program is the whole scriptSig
  if (!hexAsBuffer(script).equals(pushData({data: redeem}))) {
    return false;
  }

  const {script: p2sh} = p2shOutputScript({hash: hash160({data: redeem})});

  // The output being spent must pay to the hash of the witness program
  return p2sh.equals(spent);
};
