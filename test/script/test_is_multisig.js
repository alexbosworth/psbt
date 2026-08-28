const {equal} = require('node:assert').strict;
const test = require('node:test');

const {isMultisig} = require('./../../script');

const key1 = '21' + '02'.repeat(33);
const key2 = '21' + '03'.repeat(33);

// Test scenarios
const tests = {
  a_multisig_script_is_multisig: {
    args: {script: '51' + key1 + '51ae'},
    msg: 'A multisig script is multisig',
    result: {is_multisig: true},
  },
  a_missing_script_is_not_multisig: {
    args: {},
    msg: 'A missing script is not multisig',
    result: {is_multisig: false},
  },
  a_script_without_a_checkmultisig_op_code_is_not_multisig: {
    args: {script: '51' + key1 + '51ac'},
    msg: 'A script without a checkmultisig op code is not multisig',
    result: {is_multisig: false},
  },
  a_script_with_a_wrong_key_count_is_not_multisig: {
    args: {script: '51' + key1 + '52ae'},
    msg: 'A script with a wrong key count is not multisig',
    result: {is_multisig: false},
  },
  a_script_requiring_more_keys_than_present_is_not_multisig: {
    args: {script: '5300ae'},
    msg: 'A script requiring more keys than present is not multisig',
    result: {is_multisig: false},
  },
  a_script_with_a_non_key_element_is_not_multisig: {
    args: {script: '51' + key1 + '6052ae'},
    msg: 'A script with a non key element is not multisig',
    result: {is_multisig: false},
  },
  a_two_of_two_multisig_script_is_multisig: {
    args: {script: '52' + key1 + key2 + '52ae'},
    msg: 'A two of two multisig script is multisig',
    result: {is_multisig: true},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(isMultisig(args), result.is_multisig);

    return end();
  });
});
