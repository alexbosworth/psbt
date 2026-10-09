const {createHash} = require('node:crypto');

const hash160 = require('./hash160');
const {isP2shScript} = require('./../utxos');
const {p2wshHashByteLength} = require('./../utxos/constants');
const {witnessProgram} = require('./../utxos');

const bufferAsHex = buffer => buffer.toString('hex');
const hashStart = 2;
const sha256 = data => createHash('sha256').update(data).digest();
const versionZero = 0;

/** Find the redeem script and witness script that an output script pays to

  Supplied scripts are used first, then scripts that are already known.

  {
    [known_redeem]: <Known Redeem Script Buffer Object>
    [known_witness]: <Known Witness Script Buffer Object>
    pushed: <Redeem Scripts Pushed in Scripts By Script Hash Hex Map Object>
    redeems: <Redeem Scripts By Script Hash Hex Map Object>
    script: <Output Script Buffer Object>
    witnesses: <Witness Scripts By Script Hash Hex Map Object>
  }

  @returns
  {
    [redeem]: <Redeem Script Buffer Object>
    [witness]: <Witness Script Buffer Object>
  }
*/
module.exports = args => {
  const isP2sh = isP2shScript({script: args.script});
  const knownRedeem = args.known_redeem;
  const knownWitness = args.known_witness;
  let redeem;

  // A known redeem script is only used when it is the one the output pays to
  const redeemHash = !!knownRedeem ? hash160({data: knownRedeem}) : undefined;

  // A P2SH output pays to the hash of its redeem script
  if (isP2sh) {
    const scriptHash = args.script.subarray(hashStart, -1);

    const hash = bufferAsHex(scriptHash);
    const isKnownRedeem = !!redeemHash && redeemHash.equals(scriptHash);

    const supplied = args.redeems.get(hash) || args.pushed.get(hash);

    redeem = supplied || (isKnownRedeem ? knownRedeem : undefined);
  }

  // The witness script hash is in the output, or in the P2SH redeem script
  const {program, version} = witnessProgram({script: redeem || args.script});

  const isVersionZero = version === versionZero;

  // A P2WSH program is a version 0 program of a script hash
  const isP2wsh = isVersionZero && program.length === p2wshHashByteLength;

  // Exit early when there is no witness script hash to pay to
  if (!isP2wsh) {
    return {redeem};
  }

  // A known witness script is only used when it hashes to the program
  const witnessHash = !!knownWitness ? sha256(knownWitness) : undefined;

  const isKnownWitness = !!witnessHash && witnessHash.equals(program);

  const supplied = args.witnesses.get(bufferAsHex(program));

  const witness = supplied || (isKnownWitness ? knownWitness : undefined);

  return {redeem, witness};
};
