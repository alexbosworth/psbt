const {equal} = require('node:assert').strict;
const test = require('node:test');

const {encodeSignature} = require('./../../signatures');
const {isValidSignature} = require('./../../signatures');

const hash = Buffer.alloc(32, 1);
const order = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
const otherKey = '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27';
const publicKey = '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';
const r = '3e8c363aa97671cdba9205746916df555a955ebba74f4cae54f89cb9e654dc08';
const s = '5c79f2f1f5b27ea08462ecb76733535b18e34cdeeb9c704c96eb5b8b3ed17f89';
const signature = r + s;

const highS = (BigInt(`0x${order}`) - BigInt(`0x${s}`)).toString(16);

const encode = sig => encodeSignature({flag: 1, signature: sig});

// Test scenarios
const tests = {
  a_signature_of_the_hash_by_the_key_is_valid: {
    args: {hash, public_key: publicKey, signature},
    msg: 'A signature of the hash by the key is valid',
    result: true,
  },
  a_signature_of_another_hash_is_not_valid: {
    args: {hash: Buffer.alloc(32, 2), public_key: publicKey, signature},
    msg: 'A signature of another hash is not valid',
    result: false,
  },
  a_signature_by_another_key_is_not_valid: {
    args: {hash, public_key: otherKey, signature},
    msg: 'A signature by another key is not valid',
    result: false,
  },
  a_signature_with_a_high_s_value_is_not_valid: {
    args: {hash, public_key: publicKey, signature: r + highS.padStart(64, '0')},
    msg: 'A signature with a high s value is not valid',
    result: false,
  },
  a_signature_with_a_number_beyond_the_curve_order_is_not_valid: {
    args: {hash, public_key: publicKey, signature: order + s},
    msg: 'A signature with a number beyond the curve order is not valid',
    result: false,
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const isValid = isValidSignature({
      hash: args.hash,
      public_key: Buffer.from(args.public_key, 'hex'),
      signature: encode(args.signature),
    });

    equal(isValid, result, 'Got expected validity');

    return;
  });
});
