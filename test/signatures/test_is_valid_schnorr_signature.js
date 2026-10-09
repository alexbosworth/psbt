const {equal} = require('node:assert').strict;
const test = require('node:test');

const {isValidSchnorrSignature} = require('./../../signatures');

const hash = Buffer.alloc(32, 1);
const key = '6930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82';
const order = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
const signature = '9467c0b16af4788159ab845eeafc5a0c43260fc0ce82b6355a8c888372beae89333edace972a71fa3f1c601e4d3b004becfb57c300e1715464b487c5e05f8f5e';

// Test scenarios
const tests = {
  a_signature_of_the_hash_by_the_key_is_valid: {
    args: {hash, key, signature},
    msg: 'A signature of the hash by the key is valid',
    result: true,
  },
  a_signature_with_a_sighash_type_byte_is_valid: {
    args: {hash, key, signature: `${signature}01`},
    msg: 'A signature followed by its sighash type byte is valid',
    result: true,
  },
  a_signature_of_another_hash_is_not_valid: {
    args: {key, signature, hash: Buffer.alloc(32, 2)},
    msg: 'A signature of another hash is not valid',
    result: false,
  },
  a_key_that_is_not_on_the_curve_cannot_sign: {
    args: {hash, signature, key: '00'.repeat(32)},
    msg: 'A key that is not a point on the curve cannot sign',
    result: false,
  },
  a_signature_with_a_large_r_is_not_valid: {
    args: {hash, key, signature: order + signature.slice(64)},
    msg: 'A signature with r that is not below the curve order is not valid',
    result: false,
  },
  a_signature_with_a_large_s_is_not_valid: {
    args: {hash, key, signature: signature.slice(0, 64) + order},
    msg: 'A signature with s that is not below the curve order is not valid',
    result: false,
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const isValid = isValidSchnorrSignature({
      hash: args.hash,
      public_key: Buffer.from(args.key, 'hex'),
      signature: Buffer.from(args.signature, 'hex'),
    });

    equal(isValid, result, 'Got expected validity');

    return;
  });
});
