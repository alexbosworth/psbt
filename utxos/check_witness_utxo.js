const {OP_EQUAL} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');

const checkWitnessVersion = require('./check_witness_version');
const {nestedScriptPubElementsLen} = require('./constants');
const {p2pkhHashByteLength} = require('./constants');
const {p2shHashByteLength} = require('./constants');
const {p2wshHashByteLength} = require('./constants');
const {script} = require('./../tokens');
const {witnessScriptPubElementsLen} = require('./constants');

const {decompile} = script;

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

  const redeemScript = !redeem ? null : Buffer.from(redeem, 'hex');
  const scriptPub = Buffer.from(script, 'hex');

  const decompiledScriptPub = decompile(scriptPub);

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

    if (!hash || !redeem) {
      break;
    }

    {
      const [version, redeemScriptHash, extra] = decompile(redeemScript);

      try {
        checkWitnessVersion({version});
      } catch (err) {
        throw err;
      }

      if (!!extra) {
        throw new Error('UnexpectedElementInWitnessRedeemScript');
      }

      if (!redeemScriptHash.equals(hash)) {
        throw new Error('InvalidRedeemScriptHashForWitnessScript');
      }
    }
    break;

  case witnessScriptPubElementsLen:
    const [version, scriptHash] = decompiledScriptPub;

    try {
      checkWitnessVersion({version});
    } catch (err) {
      throw err;
    }

    switch (scriptHash.length) {
    case p2pkhHashByteLength:
    case p2wshHashByteLength:
      break;

    default:
      throw new Error('InvalidScriptHashLengthForWitnessScriptPub');
    }
    break;

  default:
    throw new Error('ExpectedWitnessScriptPubForWitnessUtxo');
  }

  return;
};
