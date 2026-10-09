const checkWitnessUtxo = require('./check_witness_utxo');
const isP2shScript = require('./is_p2sh_script');
const witnessProgram = require('./witness_program');

const hashStart = 2;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Check that the output an input spends fits the input's scripts

  {
    [hash]: <Input Redeem Script HASH160 Buffer Object>
    [output]: {
      script: <Spent Output Script Hex String>
    }
    [redeem]: <Input Redeem Script Hex String>
    [witness]: <Input Witness Script SHA256 Buffer Object>
  }

  @throws
  <Error>
*/
module.exports = ({hash, output, redeem, witness}) => {
  if (!hash && !witness) {
    throw new Error('ExpectedNonWitnessRedeemScriptHashBuffer');
  }

  // The spent output must exist in the non-witness UTXO transaction
  if (!output) {
    throw new Error('ExpectedSpentOutputInNonWitnessUtxo');
  }

  const script = hexAsBuffer(output.script);

  const isP2sh = isP2shScript({script});

  // The script hash sits between the push length and the final OP_EQUAL
  const scriptHash = script.subarray(hashStart, -1);

  // Make sure the spent output pays to the hash of the redeem script
  if (!!hash && (!isP2sh || !scriptHash.equals(hash))) {
    throw new Error('RedeemScriptDoesNotMatchUtxo');
  }

  // Exit early when there is no witness script to check
  if (!witness) {
    return;
  }

  const {program} = witnessProgram({script});

  // A witness script is only for an output paying to a script hash or program
  if (!isP2sh && !program) {
    throw new Error('WitnessScriptDoesNotMatchUtxo');
  }

  // The witness script must hash to the witness program being spent
  checkWitnessUtxo({redeem, hash: witness, script: output.script});

  return;
};
