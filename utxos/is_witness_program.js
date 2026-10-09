const {maxWitnessProgramByteLength} = require('./constants');
const {minWitnessProgramByteLength} = require('./constants');
const witnessProgram = require('./witness_program');

/** Determine if a script is exactly a witness program

  {
    script: <Script Buffer Object>
  }

  @returns
  <Is Witness Program Bool>
*/
module.exports = ({script}) => {
  const {program} = witnessProgram({script});

  if (!program || program.length < minWitnessProgramByteLength) {
    return false;
  }

  return program.length <= maxWitnessProgramByteLength;
};
