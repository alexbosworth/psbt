const {equal} = require('node:assert').strict;
const test = require('node:test');

const {bip32Path} = require('./../../bip32');

// Test scenarios
const tests = {
  a_deep_path_is_encoded: {
    args: {path: `m/84'/0'/0'/1/512`},
    msg: 'A deep path is encoded',
    result: {path: '5400008000000080000000800100000000020000'},
  },
  a_path_with_a_single_unhardened_child_is_encoded: {
    args: {path: 'm/0'},
    msg: 'A path with a single unhardened child is encoded',
    result: {path: '00000000'},
  },
  a_path_with_hardened_and_unhardened_children_is_encoded: {
    args: {path: `m/44'/0/1`},
    msg: 'A path with hardened and unhardened children is encoded',
    result: {path: '2c0000800000000001000000'},
  },
  a_path_with_the_maximum_hardened_index_is_encoded: {
    args: {path: `m/2147483647'`},
    msg: 'A path with the maximum hardened index is encoded',
    result: {path: 'ffffffff'},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(bip32Path(args).toString('hex'), result.path);

    return end();
  });
});
