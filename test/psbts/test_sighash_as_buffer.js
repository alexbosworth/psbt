const {equal} = require('node:assert').strict;
const test = require('node:test');

const sighashAsBuffer = require('./../../psbts/sighash_as_buffer');

// Test scenarios
const tests = {
  a_sighash_all_type_is_encoded_as_a_buffer: {
    args: {sighash: 1},
    msg: 'A sighash all type is encoded as a little endian buffer',
    result: {value: '01000000'},
  },
  a_sighash_single_anyonecanpay_type_is_encoded_as_a_buffer: {
    args: {sighash: 131},
    msg: 'A sighash single anyonecanpay type is encoded as a buffer',
    result: {value: '83000000'},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(sighashAsBuffer(args).toString('hex'), result.value);

    return end();
  });
});
