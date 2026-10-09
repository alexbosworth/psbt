const checkNonWitnessUtxo = require('./check_non_witness_utxo');
const checkWitnessUtxo = require('./check_witness_utxo');
const isP2shScript = require('./is_p2sh_script');
const isWitnessProgram = require('./is_witness_program');
const taprootOutputKey = require('./taproot_output_key');
const witnessProgram = require('./witness_program');

module.exports = {
  checkNonWitnessUtxo,
  checkWitnessUtxo,
  isP2shScript,
  isWitnessProgram,
  taprootOutputKey,
  witnessProgram,
};
