const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const encodePsbt = require('./../../psbts/encode_psbt');

// Test scenarios
const tests = {
  key_value_pairs_are_encoded_as_a_psbt: {
    args: {pairs: [{separator: true}]},
    msg: 'Key value pairs are encoded as a psbt',
    result: {psbt: '70736274ff00'},
  },
  pairs_are_expected_to_be_an_array: {
    args: {pairs: null},
    err: 'ExpectedKeyValuePairsToEncode',
    msg: 'Pairs are expected to be an array',
  },
  pairs_without_a_type_and_value_are_expected_to_be_separators: {
    args: {pairs: [{}]},
    err: 'ExpectedSeparator',
    msg: 'Pairs without a type and value are expected to be separators',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => encodePsbt(args), new Error(err));

      return end();
    }

    equal(encodePsbt(args).psbt, result.psbt);

    return end();
  });
});
