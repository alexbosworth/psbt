const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {taprootSighashType} = require('./../../signatures');

const signature = '9a'.repeat(64);

// Test scenarios
const tests = {
  a_signature_without_a_sighash_type_byte_uses_the_default: {
    args: {signature: Buffer.from(signature, 'hex')},
    msg: 'A 64 byte taproot signature uses the default sighash type',
    result: {hash_type: 0},
  },
  a_signature_with_a_sighash_type_byte_uses_that_type: {
    args: {signature: Buffer.from(`${signature}83`, 'hex')},
    msg: 'A 65 byte taproot signature uses the type in its last byte',
    result: {hash_type: 131},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(taprootSighashType(args), result, 'Got expected sighash type');

    return;
  });
});
