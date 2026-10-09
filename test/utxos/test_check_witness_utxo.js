const test = require('node:test');
const {throws} = require('node:assert').strict;

const {checkWitnessUtxo} = require('./../../utxos');

const nestedScriptPub = 'a914' + '11'.repeat(20) + '87';
const payingScriptPub = 'a914bd5be2e29c2eafe9b1d60da5aa8f2354a5e7568887';

// Test scenarios
const tests = {
  a_script_is_expected: {
    args: {},
    err: 'ExpectedScriptInWitnessUtxoCheck',
    msg: 'A script is expected',
  },
  a_nested_script_pub_must_start_with_a_hash160_op_code: {
    args: {script: 'ac14' + '11'.repeat(20) + '87'},
    err: 'ExpectedHash160ForNestedWitnessScriptPub',
    msg: 'A nested script pub must start with a hash160 op code',
  },
  a_nested_script_pub_must_have_a_p2sh_hash_length_hash: {
    args: {script: 'a913' + '11'.repeat(19) + '87'},
    err: 'UnexpectedHashLengthForNestedWitnessScriptPub',
    msg: 'A nested script pub must have a p2sh hash length hash',
  },
  a_nested_script_pub_must_end_with_an_equal_op_code: {
    args: {script: 'a914' + '11'.repeat(20) + 'ac'},
    err: 'UnexpectedOpCodeForNestedWitnessScriptPub',
    msg: 'A nested script pub must end with an equal op code',
  },
  a_nested_script_pub_without_a_redeem_script_passes_the_check: {
    args: {script: nestedScriptPub},
    msg: 'A nested script pub without a redeem script passes the check',
  },
  a_redeem_script_with_an_extra_element_is_rejected: {
    args: {
      hash: Buffer.alloc(20, 0x22),
      redeem: '0014' + '22'.repeat(20) + '51',
      script: nestedScriptPub,
    },
    err: 'UnexpectedElementInWitnessRedeemScript',
    msg: 'A redeem script with an extra element is rejected',
  },
  a_redeem_script_hash_that_does_not_match_is_rejected: {
    args: {
      hash: Buffer.alloc(20, 0x33),
      redeem: '0014' + '22'.repeat(20),
      script: payingScriptPub,
    },
    err: 'InvalidRedeemScriptHashForWitnessScript',
    msg: 'A redeem script hash that does not match is rejected',
  },
  a_redeem_script_hash_that_matches_passes_the_check: {
    args: {
      hash: Buffer.alloc(20, 0x22),
      redeem: '0014' + '22'.repeat(20),
      script: payingScriptPub,
    },
    msg: 'A redeem script hash that matches passes the check',
  },
  a_redeem_script_that_the_output_pays_to_passes_the_check: {
    args: {redeem: '0014' + '22'.repeat(20), script: payingScriptPub},
    msg: 'A redeem script that the output pays to passes the check',
  },
  a_redeem_script_that_the_output_does_not_pay_to_is_rejected: {
    args: {redeem: '0014' + '22'.repeat(20), script: nestedScriptPub},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A redeem script that the output does not pay to is rejected',
  },
  a_redeem_script_for_a_native_witness_output_is_rejected: {
    args: {redeem: '0014' + '22'.repeat(20), script: '0014' + '22'.repeat(20)},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A redeem script for a native witness output is rejected',
  },
  a_redeem_script_with_an_invalid_witness_version_is_rejected: {
    args: {
      hash: Buffer.alloc(32, 0x22),
      redeem: '6120' + '22'.repeat(32),
      script: nestedScriptPub,
    },
    err: 'InvalidVersionNumberForWitnessScriptPub',
    msg: 'A redeem script with an invalid witness version is rejected',
  },
  a_witness_script_pub_with_an_invalid_version_is_rejected: {
    args: {script: '6120' + '11'.repeat(32)},
    err: 'InvalidVersionNumberForWitnessScriptPub',
    msg: 'A witness script pub with an invalid version is rejected',
  },
  a_witness_script_pub_hash_must_have_a_known_hash_length: {
    args: {script: '0015' + '11'.repeat(21)},
    err: 'InvalidScriptHashLengthForWitnessScriptPub',
    msg: 'A witness script pub hash must have a known hash length',
  },
  a_version_one_taproot_program_passes_the_check: {
    args: {script: '5120' + '11'.repeat(32)},
    msg: 'A version 1 program of 32 bytes passes the check',
  },
  a_minimum_size_future_version_program_passes_the_check: {
    args: {script: '5102' + '11'.repeat(2)},
    msg: 'A version 1 program of 2 bytes passes the check',
  },
  a_maximum_size_future_version_program_passes_the_check: {
    args: {script: '6028' + '11'.repeat(40)},
    msg: 'A version 16 program of 40 bytes passes the check',
  },
  a_future_version_program_that_is_too_short_is_rejected: {
    args: {script: '5101' + '11'},
    err: 'InvalidScriptHashLengthForWitnessScriptPub',
    msg: 'A version 1 program shorter than 2 bytes is rejected',
  },
  a_future_version_program_that_is_too_long_is_rejected: {
    args: {script: '5129' + '11'.repeat(41)},
    err: 'InvalidScriptHashLengthForWitnessScriptPub',
    msg: 'A version 1 program longer than 40 bytes is rejected',
  },
  a_version_zero_program_of_another_size_is_rejected: {
    args: {script: '0028' + '11'.repeat(40)},
    err: 'InvalidScriptHashLengthForWitnessScriptPub',
    msg: 'A version 0 program that is not 20 or 32 bytes is rejected',
  },
  a_non_minimal_program_push_is_rejected: {
    args: {script: '004c141111111111111111111111111111111111111111'},
    err: 'ExpectedWitnessProgramForWitnessScriptPub',
    msg: 'A program pushed with OP_PUSHDATA1 is not a witness program',
  },
  a_one_negate_version_is_rejected: {
    args: {script: '4f141111111111111111111111111111111111111111'},
    err: 'ExpectedWitnessProgramForWitnessScriptPub',
    msg: 'An OP_1NEGATE version is not a witness program',
  },
  a_data_push_version_is_rejected: {
    args: {script: '0100141111111111111111111111111111111111111111'},
    err: 'ExpectedWitnessProgramForWitnessScriptPub',
    msg: 'A version pushed as data is not a witness program',
  },
  a_non_minimal_p2sh_push_is_rejected: {
    args: {script: 'a94c14111111111111111111111111111111111111111187'},
    err: 'ExpectedStandardP2shScriptPubForNestedWitnessUtxo',
    msg: 'A script hash pushed with OP_PUSHDATA1 is not a P2SH output',
  },
  a_non_minimal_nested_program_is_rejected: {
    args: {
      hash: Buffer.alloc(32, 0x22),
      redeem: '004c202222222222222222222222222222222222222222222222222222222222222222',
      script: 'a914111111111111111111111111111111111111111187',
    },
    err: 'ExpectedWitnessProgramForNestedRedeemScript',
    msg: 'A redeem script pushing its program with OP_PUSHDATA1 is rejected',
  },
  a_truncated_program_push_is_rejected: {
    args: {script: '5114' + '11'.repeat(19)},
    err: 'ExpectedWitnessScriptPubForWitnessUtxo',
    msg: 'A script with a truncated push is not a witness program',
  },
  a_truncated_nested_redeem_script_is_rejected: {
    args: {
      hash: Buffer.alloc(32, 0x22),
      redeem: '0020' + '22'.repeat(31),
      script: 'a914' + '11'.repeat(20) + '87',
    },
    err: 'ExpectedWitnessVersion',
    msg: 'A redeem script with a truncated push is rejected',
  },
  a_witness_script_matching_a_native_output_passes_the_check: {
    args: {hash: Buffer.alloc(32, 0x44), script: '0020' + '44'.repeat(32)},
    msg: 'A witness script that hashes to the output program passes',
  },
  a_witness_script_not_matching_a_native_output_is_rejected: {
    args: {hash: Buffer.alloc(32, 0x55), script: '0020' + '44'.repeat(32)},
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script not hashing to the output program is rejected',
  },
  a_witness_script_for_a_public_key_hash_output_is_rejected: {
    args: {hash: Buffer.alloc(32, 0x44), script: '0014' + '44'.repeat(20)},
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script for a public key hash output is rejected',
  },
  an_ordinary_redeem_script_without_a_witness_script_is_rejected: {
    args: {
      redeem: '51',
      script: 'a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87',
    },
    err: 'ExpectedWitnessProgramForNestedRedeemScript',
    msg: 'A redeem script that is not a witness program is rejected',
  },
  a_version_0_redeem_program_with_an_invalid_length_is_rejected: {
    args: {
      redeem: '0019' + '22'.repeat(25),
      script: 'a914fb87edf4c191820a4d1e7aa89f5aaf0a6efc887887',
    },
    err: 'InvalidProgramLengthForNestedRedeemScript',
    msg: 'A version 0 redeem program not 20 or 32 bytes long is rejected',
  },
  a_later_version_redeem_program_that_is_too_long_is_rejected: {
    args: {
      redeem: '5129' + '22'.repeat(41),
      script: 'a9147bdaf3b653444565c93c28c9b708fd9056b92a2887',
    },
    err: 'InvalidProgramLengthForNestedRedeemScript',
    msg: 'A later version redeem program longer than 40 bytes is rejected',
  },
  an_empty_redeem_script_is_checked: {
    args: {
      redeem: '',
      script: 'a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87',
    },
    err: 'ExpectedWitnessVersion',
    msg: 'An empty redeem script is checked rather than treated as missing',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => checkWitnessUtxo(args), new Error(err));

      return end();
    }

    checkWitnessUtxo(args);

    return end();
  });
});
