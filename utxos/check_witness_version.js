const {maxWitnessVersion} = require('./constants');
const {minWitnessVersion} = require('./constants');

/** Check that a witness version is correct

  {
    version: <Version Number>
  }

  @throws
  <ExpectedWitnessVersion Error>
  <InvalidVersionNumberForWitnessScriptPub Error>
*/
module.exports = ({version}) => {
  if (version === null || version === undefined) {
    throw new Error('ExpectedWitnessVersion');
  }

  if (version < minWitnessVersion || version > maxWitnessVersion) {
    throw new Error('InvalidVersionNumberForWitnessScriptPub');
  }

  return;
};
