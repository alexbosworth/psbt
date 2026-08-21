const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeSignature} = require('./../../signatures');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// Test scenarios
const tests = {
  a_der_encoded_signature_is_decoded: {
    args: {
      signature: hexAsBuffer('30260202010202201fe2f26cd90d6b04ce4a9a4c1c5d6' +
        '1db08e2c04d1c72c17f3546c6dfcfb17a4501'),
    },
    msg: 'A DER encoded signature is decoded',
    result: {
      hash_type: 1,
      signature: '00000000000000000000000000000000000000000000000000000000' +
        '000001021fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
        'fb17a45',
    },
  },
  a_signature_with_a_padded_r_value_is_decoded: {
    args: {
      signature: hexAsBuffer('3045022100ffe2f26cd90d6b04ce4a9a4c1c5d61db08e' +
        '2c04d1c72c17f3546c6dfcfb17a4502201fe2f26cd90d6b04ce4a9a4c1c5d61db' +
        '08e2c04d1c72c17f3546c6dfcfb17a4582'),
    },
    msg: 'A signature with a padded r value is decoded',
    result: {
      hash_type: 130,
      signature: 'ffe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6df' +
        'cfb17a451fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
        'fb17a45',
    },
  },
  a_signature_that_is_not_a_buffer_is_rejected: {
    args: {signature: 'signature'},
    err: 'ExpectedSignatureBufferToDecode',
    msg: 'A signature that is not a buffer is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => decodeSignature(args), new Error(err));

      return end();
    }

    const decoded = decodeSignature(args);

    equal(decoded.hash_type, result.hash_type);
    equal(decoded.signature.toString('hex'), result.signature);

    return end();
  });
});
