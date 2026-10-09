const {equal} = require('node:assert').strict;
const test = require('node:test');

const {isBip32Path} = require('./../../bip32');

// Test scenarios
const tests = {
  a_path_with_hardened_and_normal_indexes_is_valid: {
    args: {path: "m/84'/0'/0'/1/5"},
    msg: 'A path with hardened and normal child indexes is valid',
    result: true,
  },
  the_master_key_path_is_valid: {
    args: {path: 'm'},
    msg: 'The path of the master key itself is valid',
    result: true,
  },
  a_path_that_is_not_a_string_is_invalid: {
    args: {path: 1},
    msg: 'A path that is not a string is invalid',
    result: false,
  },
  a_path_without_the_master_key_is_invalid: {
    args: {path: "0'/1"},
    msg: 'A path that does not start at the master key is invalid',
    result: false,
  },
  a_path_with_a_fractional_index_is_invalid: {
    args: {path: 'm/1.5'},
    msg: 'A path with a fractional child index is invalid',
    result: false,
  },
  a_path_with_an_index_beyond_the_hardened_offset_is_invalid: {
    args: {path: 'm/2147483648'},
    msg: 'A path with a child index beyond the hardened offset is invalid',
    result: false,
  },
  a_path_with_millions_of_children_is_valid: {
    args: {path: `m${'/0'.repeat(5e6)}`},
    msg: 'A path with millions of child indexes is checked',
    result: true,
  },
  a_path_with_an_empty_child_is_invalid: {
    args: {path: 'm/0/'},
    msg: 'A path with an empty child index is invalid',
    result: false,
  },
  a_path_with_a_child_hardened_twice_is_invalid: {
    args: {path: "m/0''"},
    msg: 'A path with a child index hardened twice is invalid',
    result: false,
  },
  a_path_from_an_upper_case_master_key_is_invalid: {
    args: {path: 'M/0'},
    msg: 'A path that does not start with a lower case m is invalid',
    result: false,
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    equal(isBip32Path(args), result, 'Got expected result');

    return;
  });
});
