const {createHash} = require('node:crypto');

const {scriptAsScriptElements} = require('@alexbosworth/blockchain');
const {OP_EQUAL} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');

const checkWitnessVersion = require('./check_witness_version');
const isWitnessProgramLength = require('./is_witness_program_length');
const {nestedScriptPubElementsLen} = require('./constants');
const {p2shHashByteLength} = require('./constants');
const witnessProgram = require('./witness_program');
const {witnessScriptPubElementsLen} = require('./constants');

const asElements = script => scriptAsScriptElements({script}).elements;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const p2shScriptByteLength = 23;

/** Check that an input's witness UTXO is valid

  {
    [hash]: <Witness Script Hash Buffer Object>
    [redeem]: <Redeem Script Hex String>
    script: <Witness UTXO Script PubKey Hex String>
  }

  @throws
  <Error>
*/
module.exports = ({hash, redeem, script}) => {
  if (!script) {
    throw new Error('ExpectedScriptInWitnessUtxoCheck');
  }

  // Scripts that cannot be decoded have no elements
  const decompiledScriptPub = asElements(script) || [];

  switch (decompiledScriptPub.length) {
  case nestedScriptPubElementsLen:
    const [hash160, nestedScriptHash, isEqual] = decompiledScriptPub;

    if (hash160 !== OP_HASH160) {
      throw new Error('ExpectedHash160ForNestedWitnessScriptPub');
    }

    if (nestedScriptHash.length !== p2shHashByteLength) {
      throw new Error('UnexpectedHashLengthForNestedWitnessScriptPub');
    }

    if (isEqual !== OP_EQUAL) {
      throw new Error('UnexpectedOpCodeForNestedWitnessScriptPub');
    }

    // The script hash must be pushed directly, exactly as in a P2SH output
    if (hexAsBuffer(script).length !== p2shScriptByteLength) {
      throw new Error('ExpectedStandardP2shScriptPubForNestedWitnessUtxo');
    }

    // Without a redeem script there is nothing more to check
    if (redeem === undefined) {
      break;
    }

    // A redeem script for a nested witness output is a witness program
    {
      const [version, , extra] = asElements(redeem) || [];

      try {
        checkWitnessVersion({version});
      } catch (err) {
        throw err;
      }

      if (!!extra) {
        throw new Error('UnexpectedElementInWitnessRedeemScript');
      }

      const redeemScript = hexAsBuffer(redeem);

      const nested = witnessProgram({script: redeemScript});

      // The redeem script must be exactly a witness program
      if (!nested.program) {
        throw new Error('ExpectedWitnessProgramForNestedRedeemScript');
      }

      if (!isWitnessProgramLength(nested)) {
        throw new Error('InvalidProgramLengthForNestedRedeemScript');
      }

      const redeemSha256 = createHash('sha256').update(redeemScript).digest();

      const scriptHash = createHash('ripemd160').update(redeemSha256).digest();

      // A redeem script must be the script that the output pays to
      if (!scriptHash.equals(nestedScriptHash)) {
        throw new Error('RedeemScriptDoesNotMatchUtxo');
      }

      // A witness script hash must be the program of the redeem script
      if (!!hash && !nested.program.equals(hash)) {
        throw new Error('InvalidRedeemScriptHashForWitnessScript');
      }
    }
    break;

  case witnessScriptPubElementsLen:
    const [version] = decompiledScriptPub;

    try {
      checkWitnessVersion({version});
    } catch (err) {
      throw err;
    }

    const witness = witnessProgram({script: hexAsBuffer(script)});

    // The bytes must be exactly a version and then a direct program push
    if (!witness.program) {
      throw new Error('ExpectedWitnessProgramForWitnessScriptPub');
    }

    if (!isWitnessProgramLength(witness)) {
      throw new Error('InvalidScriptHashLengthForWitnessScriptPub');
    }

    // Only an output that pays to a script hash is spent with a redeem script
    if (redeem !== undefined) {
      throw new Error('RedeemScriptDoesNotMatchUtxo');
    }

    // A witness script hash must be the program of the output it spends
    if (!!hash && !witness.program.equals(hash)) {
      throw new Error('WitnessScriptDoesNotMatchUtxo');
    }
    break;

  default:
    throw new Error('ExpectedWitnessScriptPubForWitnessUtxo');
  }

  return;
};
