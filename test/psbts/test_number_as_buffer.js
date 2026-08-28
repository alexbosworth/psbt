const {equal} = require('node:assert').strict;
const test = require('node:test');

const numberAsBuffer = require('./../../psbts/number_as_buffer');

// Test scenarios
const tests = {
  a_number_is_encoded_as_a_minimal_buffer: {
    args: {number: 81},
    msg: 'A number is encoded as a minimal buffer',
    result: {value: '51'},
  },
  a_zero_number_is_encoded_as_a_single_byte: {
    args: {number: 0},
    msg: 'A zero number is encoded as a single byte',
    result: {value: '00'},
  },
  a_number_with_an_odd_length_hex_encoding_is_zero_padded: {
    args: {number: 300},
    msg: 'A number with an odd length hex encoding is zero padded',
    result: {value: '012c'},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(numberAsBuffer(args).toString('hex'), result.value);

    return end();
  });
});
