const test = require('node:test');
const {throws} = require('node:assert').strict;

const {checkNonWitnessUtxo} = require('./../../utxos');

const hash = Buffer.alloc(20, 0xaa);
const nested = '822c8d4b99ef1369e189aa670faa749c1f928864';
const nestedRedeem = '0020' + '44'.repeat(32);
const p2sh = {script: `a914${'aa'.repeat(20)}87`};
const p2wsh = {script: '0020' + '44'.repeat(32)};
const witness = Buffer.alloc(32, 0x44);

// Test scenarios
const tests = {
  a_matching_p2sh_output_passes_the_check: {
    args: {hash, output: p2sh},
    msg: 'A spent p2sh output that matches the redeem script passes',
  },
  a_redeem_script_hash_is_expected: {
    args: {output: p2sh},
    err: 'ExpectedNonWitnessRedeemScriptHashBuffer',
    msg: 'A redeem script hash is expected',
  },
  a_spent_output_is_expected: {
    args: {hash},
    err: 'ExpectedSpentOutputInNonWitnessUtxo',
    msg: 'The spent output is expected to exist in the utxo',
  },
  a_spent_output_with_a_different_hash_is_rejected: {
    args: {hash: Buffer.alloc(20, 0xbb), output: p2sh},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A spent output paying to a different script hash is rejected',
  },
  a_spent_output_that_is_not_p2sh_is_rejected: {
    args: {hash, output: {script: `0014${'aa'.repeat(20)}`}},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A spent output that is not p2sh is rejected',
  },
  a_spent_output_with_extra_elements_is_rejected: {
    args: {hash, output: {script: `${p2sh.script}00`}},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A p2sh-like spent output with an extra element is rejected',
  },
  a_spent_output_with_a_non_minimal_push_is_rejected: {
    args: {hash, output: {script: `a94c14${'aa'.repeat(20)}87`}},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A spent output pushing its hash with OP_PUSHDATA1 is rejected',
  },
  a_native_witness_output_with_a_matching_witness_script_passes: {
    args: {witness, output: p2wsh},
    msg: 'A witness script that hashes to the spent witness program passes',
  },
  a_native_witness_output_with_a_different_witness_script_is_rejected: {
    args: {output: p2wsh, witness: Buffer.alloc(32, 0x55)},
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script not hashing to the spent program is rejected',
  },
  a_nested_witness_output_with_a_matching_witness_script_passes: {
    args: {
      witness,
      hash: Buffer.from(nested, 'hex'),
      output: {script: `a914${nested}87`},
      redeem: nestedRedeem,
    },
    msg: 'A witness script that hashes to the redeem script program passes',
  },
  a_redeem_program_that_does_not_match_the_witness_script_is_rejected: {
    args: {
      hash: Buffer.from(nested, 'hex'),
      output: {script: `a914${nested}87`},
      redeem: nestedRedeem,
      witness: Buffer.alloc(32, 0x55),
    },
    err: 'InvalidRedeemScriptHashForWitnessScript',
    msg: 'A redeem program not matching the witness script is rejected',
  },
  an_ordinary_redeem_script_with_a_witness_script_is_rejected: {
    args: {
      witness,
      hash: Buffer.from('da1745e9b549bd0bfa1a569971c77eba30cd5a4b', 'hex'),
      output: {script: 'a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87'},
      redeem: '51',
    },
    err: 'ExpectedWitnessProgramForNestedRedeemScript',
    msg: 'A redeem script that is not a witness program is rejected',
  },
  a_witness_script_for_an_output_without_a_program_is_rejected: {
    args: {witness, output: {script: `76a914${'11'.repeat(20)}88ac`}},
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script for an output with no witness program is rejected',
  },
  a_witness_script_without_a_redeem_script_for_p2sh_passes: {
    args: {witness, output: p2sh},
    msg: 'A witness script for p2sh without a redeem script passes',
  },
  a_spent_output_is_expected_for_a_witness_script: {
    args: {witness},
    err: 'ExpectedSpentOutputInNonWitnessUtxo',
    msg: 'The spent output is expected when checking a witness script',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => checkNonWitnessUtxo(args), new Error(err));

      return end();
    }

    checkNonWitnessUtxo(args);

    return end();
  });
});
