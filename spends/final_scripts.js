const {p2pkhOutputScript} = require('@alexbosworth/blockchain');

const {isP2shScript} = require('./../utxos');
const {isWitnessProgram} = require('./../utxos');
const {p2pkhHashByteLength} = require('./../utxos/constants');
const {p2wshHashByteLength} = require('./../utxos/constants');
const {pushData} = require('./../script');
const satisfyingStack = require('./satisfying_stack');
const {witnessProgram} = require('./../utxos');

const asPushes = items => Buffer.concat(items.map(data => pushData({data})));
const taprootKeyByteLength = 32;
const taprootVersion = 1;
const versionZero = 0;

/** Make the final scripts that spend an output

  The kind of spend comes from the script of the output that is spent

  {
    [redeem]: <Redeem Script Buffer Object>
    script: <Spent Output Script Buffer Object>
    signatures: [{
      is_valid: <Signature Is Valid Bool>
      public_key: <Public Key Buffer Object>
      signature: <Signature Buffer Object>
    }]
    [tap_key_sig]: {
      is_valid: <Signature Is Valid Bool>
      signature: <Taproot Key Spend Signature Buffer Object>
    }
    [witness]: <Witness Script Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    [script_sig]: <Final ScriptSig Buffer Object>
    [witness]: [<Final Script Witness Stack Element Buffer Object>]
  }
*/
module.exports = ({redeem, script, signatures, tap_key_sig, witness}) => {
  const isP2sh = isP2shScript({script});

  // A P2SH output is spent with the redeem script that it pays to
  if (isP2sh && redeem === undefined) {
    throw new Error('ExpectedRedeemScriptToFinalizeInput');
  }

  // The script being spent is the redeem script when the output is P2SH
  const spent = isP2sh ? redeem : script;

  // A script that is not a witness program is satisfied by the scriptSig
  if (!isWitnessProgram({script: spent})) {
    const {stack} = satisfyingStack({signatures, script: spent});

    // A redeem script is pushed after the elements that satisfy it
    return {script_sig: asPushes(isP2sh ? [...stack, redeem] : stack)};
  }

  const {program, version} = witnessProgram({script: spent});

  // A witness program nested in P2SH is pushed alone in the scriptSig
  const scriptSig = isP2sh ? pushData({data: redeem}) : undefined;

  const isVersionOne = version === taprootVersion;

  // A taproot output is spent with its key spend signature
  if (!isP2sh && isVersionOne && program.length === taprootKeyByteLength) {
    if (!tap_key_sig) {
      throw new Error('ExpectedTaprootKeySpendSignatureToFinalizeInput');
    }

    if (!tap_key_sig.is_valid) {
      throw new Error('ExpectedValidTaprootKeySpendSignatureToFinalizeInput');
    }

    return {witness: [tap_key_sig.signature]};
  }

  // Other witness versions are not spent with signatures and scripts
  if (version !== versionZero) {
    throw new Error('UnsupportedScriptTypeToFinalize');
  }

  // A public key hash program is satisfied like a P2PKH script of the hash
  if (program.length === p2pkhHashByteLength) {
    const {script: keyHashScript} = p2pkhOutputScript({hash: program});

    const {stack} = satisfyingStack({signatures, script: keyHashScript});

    return {script_sig: scriptSig, witness: stack};
  }

  // Version 0 programs are either a public key hash or a script hash
  if (program.length !== p2wshHashByteLength) {
    throw new Error('UnsupportedScriptTypeToFinalize');
  }

  if (witness === undefined) {
    throw new Error('ExpectedWitnessScriptToFinalizeInput');
  }

  const {stack} = satisfyingStack({signatures, script: witness});

  // A witness script is the last element, after the elements that satisfy it
  return {script_sig: scriptSig, witness: [...stack, witness]};
};
