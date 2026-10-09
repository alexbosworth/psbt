const {equal} = require('node:assert').strict;
const test = require('node:test');

const {isP2shScript} = require('./../../utxos');

// Test scenarios
const tests = {
  a_p2sh_script_is_a_p2sh_script: {
    args: {script: 'a914' + '11'.repeat(20) + '87'},
    msg: 'A P2SH output script is a P2SH script',
    result: true,
  },
  a_script_of_another_length_is_not_a_p2sh_script: {
    args: {script: 'a915' + '11'.repeat(21) + '87'},
    msg: 'A script of another length is not a P2SH script',
    result: false,
  },
  a_script_without_hash160_is_not_a_p2sh_script: {
    args: {script: 'a814' + '11'.repeat(20) + '87'},
    msg: 'A script that does not start with OP_HASH160 is not a P2SH script',
    result: false,
  },
  a_script_with_another_push_is_not_a_p2sh_script: {
    args: {script: 'a94c' + '11'.repeat(20) + '87'},
    msg: 'A script that does not push the hash directly is not a P2SH script',
    result: false,
  },
  a_script_without_equal_is_not_a_p2sh_script: {
    args: {script: 'a914' + '11'.repeat(20) + '88'},
    msg: 'A script that does not end with OP_EQUAL is not a P2SH script',
    result: false,
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const script = Buffer.from(args.script, 'hex');

    equal(isP2shScript({script}), result, 'Got expected result');

    return;
  });
});
