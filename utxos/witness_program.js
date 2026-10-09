const {OP_0} = require('bitcoin-ops');
const {OP_1} = require('bitcoin-ops');
const {OP_16} = require('bitcoin-ops');
const {OP_PUSHDATA1} = require('bitcoin-ops');

const programStart = 2;
const versionZero = 0;

/** Read the version and program of a script that is exactly a witness program

  {
    script: <Script Buffer Object>
  }

  @returns
  {
    [program]: <Witness Program Buffer Object>
    [version]: <Witness Version Number>
  }
*/
module.exports = ({script}) => {
  const [opCode, pushLength] = script;

  const isVersion = opCode === OP_0 || (opCode >= OP_1 && opCode <= OP_16);

  // The version is OP_0, or one of OP_1 through OP_16
  if (!isVersion) {
    return {};
  }

  // The program is one direct push of all of the bytes after the version
  if (pushLength >= OP_PUSHDATA1) {
    return {};
  }

  if (pushLength !== script.length - programStart) {
    return {};
  }

  return {
    program: script.subarray(programStart),
    version: opCode === OP_0 ? versionZero : opCode - OP_1 + 1,
  };
};
