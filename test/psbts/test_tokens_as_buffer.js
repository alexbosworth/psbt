const {equal} = require('node:assert').strict;
const test = require('node:test');

const tokensAsBuffer = require('./../../psbts/tokens_as_buffer');

// Test scenarios
const tests = {
  a_tokens_value_is_encoded_as_a_buffer: {
    args: {tokens: 100000000},
    msg: 'A tokens value is encoded as a little endian value buffer',
    result: {value: '00e1f50500000000'},
  },
  a_zero_tokens_value_is_encoded_as_a_buffer: {
    args: {tokens: 0},
    msg: 'A zero tokens value is encoded as a little endian value buffer',
    result: {value: '0000000000000000'},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(tokensAsBuffer(args).toString('hex'), result.value);

    return end();
  });
});
