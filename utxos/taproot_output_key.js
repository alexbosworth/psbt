const witnessProgram = require('./witness_program');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const taprootKeyByteLength = 32;
const taprootVersion = 1;

/** Get the output key of a taproot output script

  A taproot output script is a version 1 witness program of a 32 byte key

  {
    [script]: <Output Script Hex String>
  }

  @returns
  {
    [output_key]: <Taproot Output X Only Public Key Hex String>
  }
*/
module.exports = ({script}) => {
  // Exit early when there is no output script
  if (script === undefined) {
    return {};
  }

  const {program, version} = witnessProgram({script: hexAsBuffer(script)});

  // Exit early when the script is not a taproot output script
  if (version !== taprootVersion || program.length !== taprootKeyByteLength) {
    return {};
  }

  return {output_key: bufferAsHex(program)};
};
