const test = require('node:test');
const {throws} = require('node:assert').strict;

const checkWitnessVersion = require('./../../utxos/check_witness_version');

// Test scenarios
const tests = {
  a_valid_witness_version_passes_the_check: {
    args: {version: 0},
    msg: 'A valid witness version passes the check',
  },
  a_witness_version_is_expected: {
    args: {},
    err: 'ExpectedWitnessVersion',
    msg: 'A witness version is expected',
  },
  a_witness_version_above_the_maximum_is_rejected: {
    args: {version: 97},
    err: 'InvalidVersionNumberForWitnessScriptPub',
    msg: 'A witness version above the maximum is rejected',
  },
  a_witness_version_below_the_minimum_is_rejected: {
    args: {version: -1},
    err: 'InvalidVersionNumberForWitnessScriptPub',
    msg: 'A witness version below the minimum is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => checkWitnessVersion(args), new Error(err));

      return end();
    }

    checkWitnessVersion(args);

    return end();
  });
});
