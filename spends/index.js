const finalizeInputPairs = require('./finalize_input_pairs');
const hash160 = require('./hash160');
const inputSighashType = require('./input_sighash_type');
const inputSpend = require('./input_spend');
const inputSpentOutput = require('./input_spent_output');
const isNestedWitnessSpend = require('./is_nested_witness_spend');
const matchingDerivations = require('./matching_derivations');
const paidKeySignatures = require('./paid_key_signatures');
const paidScripts = require('./paid_scripts');
const scriptSigningKeys = require('./script_signing_keys');
const signedSpend = require('./signed_spend');
const spentOutputs = require('./spent_outputs');
const taprootKeySpendSignature = require('./taproot_key_spend_signature');
const taprootSigningKey = require('./taproot_signing_key');

module.exports = {
  finalizeInputPairs,
  hash160,
  inputSighashType,
  inputSpend,
  inputSpentOutput,
  isNestedWitnessSpend,
  matchingDerivations,
  paidKeySignatures,
  paidScripts,
  scriptSigningKeys,
  signedSpend,
  spentOutputs,
  taprootKeySpendSignature,
  taprootSigningKey,
};
