const {createHash} = require('node:crypto');

const {checkNonWitnessUtxo} = require('./../utxos');
const hash160 = require('./../spends/hash160');

const bufferAsHex = buffer => buffer.toString('hex');
const sha256 = data => createHash('sha256').update(data).digest();

/** Check that the scripts of a PSBT output are scripts that the output pays

  {
    [redeem]: <Redeem Script Buffer Object>
    script: <Output Script Hex String>
    [witness]: <Witness Script Buffer Object>
  }

  @throws
  <RedeemScriptDoesNotMatchOutput Error>
  <WitnessScriptDoesNotMatchOutput Error>
  <Error>
*/
module.exports = ({redeem, script, witness}) => {
  const hasRedeem = redeem !== undefined;
  const hasWitness = witness !== undefined;

  // Exit early when the output has no scripts to check
  if (!hasRedeem && !hasWitness) {
    return;
  }

  // Output scripts are checked the same way as the scripts of a spent output
  try {
    checkNonWitnessUtxo({
      hash: hasRedeem ? hash160({data: redeem}) : undefined,
      output: {script},
      redeem: hasRedeem ? bufferAsHex(redeem) : undefined,
      witness: hasWitness ? sha256(witness) : undefined,
    });
  } catch (err) {
    if (err.message === 'RedeemScriptDoesNotMatchUtxo') {
      throw new Error('RedeemScriptDoesNotMatchOutput');
    }

    if (err.message === 'WitnessScriptDoesNotMatchUtxo') {
      throw new Error('WitnessScriptDoesNotMatchOutput');
    }

    throw err;
  }

  return;
};
