const {maxWitnessProgramByteLength} = require('./constants');
const {minWitnessProgramByteLength} = require('./constants');
const {p2pkhHashByteLength} = require('./constants');
const {p2wshHashByteLength} = require('./constants');

const versionZero = 0;

/** Determine if a witness program has a valid length for its version

  {
    program: <Witness Program Buffer Object>
    version: <Witness Version Number>
  }

  @returns
  <Has Valid Program Length Bool>
*/
module.exports = ({program, version}) => {
  if (version === versionZero) {
    return [p2pkhHashByteLength, p2wshHashByteLength].includes(program.length);
  }

  if (program.length < minWitnessProgramByteLength) {
    return false;
  }

  return program.length <= maxWitnessProgramByteLength;
};
