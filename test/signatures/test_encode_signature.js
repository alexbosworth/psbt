const {equal} = require('node:assert').strict;
const test = require('node:test');

const {encodeSignature} = require('./../../signatures');

// Test scenarios
const tests = {
  a_signature_with_a_high_first_bit_r_value_is_encoded: {
    args: {
      flag: 130,
      signature: 'ffe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
        'fb17a451fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfcf' +
        'b17a45',
    },
    msg: 'A signature with a high first bit r value is encoded',
    result: {
      signature: '3045022100ffe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c1' +
        '7f3546c6dfcfb17a4502201fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c7' +
        '2c17f3546c6dfcfb17a4582',
    },
  },
  a_signature_with_a_leading_zeros_r_value_is_encoded: {
    args: {
      flag: 1,
      signature: '00000000000000000000000000000000000000000000000000000000' +
        '000001021fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
        'fb17a45',
    },
    msg: 'A signature with a leading zeros r value is encoded',
    result: {
      signature: '30260202010202201fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d' +
        '1c72c17f3546c6dfcfb17a4501',
    },
  },
  a_signature_with_a_zero_r_value_is_encoded: {
    args: {
      flag: 1,
      signature: '00000000000000000000000000000000000000000000000000000000' +
        '000000001fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
        'fb17a45',
    },
    msg: 'A signature with a zero r value is encoded',
    result: {
      signature: '302502010002201fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c' +
        '72c17f3546c6dfcfb17a4501',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(encodeSignature(args).toString('hex'), result.signature);

    return end();
  });
});
