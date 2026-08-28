const test = require('node:test');
const {throws} = require('node:assert').strict;

const {checkWitnessUtxo} = require('./../../utxos');

const nestedScriptPub = 'a914' + '11'.repeat(20) + '87';

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
      script: nestedScriptPub,
    },
    err: 'InvalidRedeemScriptHashForWitnessScript',
    msg: 'A redeem script hash that does not match is rejected',
  },
  a_redeem_script_hash_that_matches_passes_the_check: {
    args: {
      hash: Buffer.alloc(20, 0x22),
      redeem: '0014' + '22'.repeat(20),
      script: nestedScriptPub,
    },
    msg: 'A redeem script hash that matches passes the check',
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
