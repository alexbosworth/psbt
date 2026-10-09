const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {taprootSigningKey} = require('./../../spends');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const internalKey = '9583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f';
const privateKey = '2c6ba77e9184c5b6c6215f84ef0e00558884dec7d23a027f0573d11bf77aff46';
const scriptTreeKey = 'dbb8de44d1c58fdd98bfb979e1ab3a00b7304c72c2122cf8c0ad00ae1705c23a';

// Test scenarios
const tests = {
  a_key_of_the_output_key_signs: {
    args: {
      input: {},
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: internalKey,
      tweaked: [],
    },
    msg: 'A signing key that is the output key signs for it',
    result: {private_key: privateKey},
  },
  a_key_tweaked_without_a_script_tree_signs: {
    args: {
      input: {},
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: '9ccc1cfb098556122565534573f28f154e06805cad2ccc7d8fc69dd3e002500f',
      tweaked: [{
        key: '9ccc1cfb098556122565534573f28f154e06805cad2ccc7d8fc69dd3e002500f',
        private_key: 'ee1b0034be8ba6d906648c554a5ac41491682eb7a0c3cd19d92688a64b46e957',
      }],
    },
    msg: 'A signing key tweaked without a script tree signs for its output',
    result: {
      private_key: 'ee1b0034be8ba6d906648c554a5ac41491682eb7a0c3cd19d92688a64b46e957',
    },
  },
  an_internal_key_tweaked_with_the_merkle_root_signs: {
    args: {
      input: {
        taproot_internal_key: internalKey,
        taproot_root_hash: '5b'.repeat(32),
      },
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: scriptTreeKey,
      tweaked: [],
    },
    msg: 'An internal key tweaked with the merkle root signs for the output',
    result: {
      private_key: 'abaedec3a96b4e0bc4900acb9a01edc06c00f6d311305c519206b6bce72b8768',
    },
  },
  an_internal_key_with_another_merkle_root_does_not_sign: {
    args: {
      input: {
        taproot_internal_key: internalKey,
        taproot_root_hash: '5c'.repeat(32),
      },
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: scriptTreeKey,
      tweaked: [],
    },
    msg: 'An internal key with another merkle root does not sign',
    result: {},
  },
  an_internal_key_without_a_merkle_root_is_not_tweaked_with_one: {
    args: {
      input: {taproot_internal_key: internalKey},
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: scriptTreeKey,
      tweaked: [],
    },
    msg: 'An internal key is not tweaked with a merkle root it does not have',
    result: {},
  },
  an_internal_key_that_is_not_a_signing_key_does_not_sign: {
    args: {
      input: {
        taproot_internal_key: '77'.repeat(32),
        taproot_root_hash: '5b'.repeat(32),
      },
      keys: [{key: internalKey, private_key: privateKey}],
      output_key: scriptTreeKey,
      tweaked: [],
    },
    msg: 'An internal key that is not a signing key does not sign',
    result: {},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const asKeys = list => new Map(list.map(n => [
      n.key,
      {private_key: hexAsBuffer(n.private_key)},
    ]));

    const {private_key} = taprootSigningKey({
      input: args.input,
      keys: asKeys(args.keys),
      output_key: args.output_key,
      tweaked: asKeys(args.tweaked),
    });

    const got = !private_key ? {} : {private_key: bufferAsHex(private_key)};

    strictSame(got, result, 'Got expected signing key');

    return;
  });
});
