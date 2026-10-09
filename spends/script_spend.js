const {p2pkhOutputScript} = require('@alexbosworth/blockchain');

const {isWitnessProgram} = require('./../utxos');
const {p2pkhHashByteLength} = require('./../utxos/constants');
const {p2wshHashByteLength} = require('./../utxos/constants');
const {witnessProgram} = require('./../utxos');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const versionZero = 0;

/** Determine how a script that an input spends is signed

  {
    script: <Spent Script Hex String>
    [witness]: <Witness Script Hex String>
  }

  @returns
  {
    [is_witness]: <Script Is Signed as a Version 0 Witness Program Bool>
    [script]: <Script Code Hex String>
  }
*/
module.exports = ({script, witness}) => {
  const spent = hexAsBuffer(script);

  // A script that is not a witness program is signed as a legacy script
  if (!isWitnessProgram({script: spent})) {
    return {script, is_witness: false};
  }

  const {program, version} = witnessProgram({script: spent});

  // Only version 0 witness programs are signed with ECDSA signatures
  if (version !== versionZero) {
    return {};
  }

  // A public key hash program is signed as a pay to public key hash script
  if (program.length === p2pkhHashByteLength) {
    const p2pkh = p2pkhOutputScript({hash: program});

    return {is_witness: true, script: bufferAsHex(p2pkh.script)};
  }

  // A script hash program is signed with the witness script that it hashes
  if (program.length === p2wshHashByteLength && witness !== undefined) {
    return {is_witness: true, script: witness};
  }

  return {};
};
