const {deepEqual} = require('node:assert').strict;
const test = require('node:test');

const {encodeDerivations} = require('./../../bip32');

// Test scenarios
const tests = {
  a_taproot_derivation_with_multiple_leaf_hashes_is_encoded: {
    args: {
      bip32_derivations: [{
        fingerprint: '00000004',
        leaf_hashes: [
          '1fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfcfb17a45',
          '2ee2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfcfb17a52',
        ],
        path: 'm/1',
        public_key: 'bbbb047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7aba' +
          'c09b95c70bb',
      }],
    },
    msg: 'A taproot derivation with multiple leaf hashes is encoded',
    result: {
      legacy: [],
      taproot: [{
        key: 'bbbb047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c7' +
          '0bb',
        value: '021fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
          'fb17a452ee2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
          'fb17a520000000401000000',
      }],
    },
  },
  a_taproot_key_spend_derivation_with_no_leaf_hashes_is_encoded: {
    args: {
      bip32_derivations: [{
        fingerprint: 'fffffffe',
        leaf_hashes: [],
        path: `m/86'/0'/0'/0/0`,
        public_key: 'aaaa047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7aba' +
          'c09b95c70aa',
      }],
    },
    msg: 'A taproot key spend derivation with no leaf hashes is encoded',
    result: {
      legacy: [],
      taproot: [{
        key: 'aaaa047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c7' +
          '0aa',
        value: '00fffffffe5600008000000080000000800000000000000000',
      }],
    },
  },
  an_empty_derivations_list_is_encoded_as_empty_lists: {
    args: {bip32_derivations: []},
    msg: 'An empty derivations list is encoded as empty lists',
    result: {legacy: [], taproot: []},
  },
  derivations_are_encoded_as_legacy_and_taproot_values: {
    args: {
      bip32_derivations: [
        {
          fingerprint: '00000001',
          path: `m/0'/0/1`,
          public_key: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7ab' +
            'ac09b95c709ee5',
        },
        {
          fingerprint: '00000002',
          leaf_hashes: [
            '1fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfcfb17a45',
          ],
          path: `m/86'/0'/0'/0/0`,
          public_key: 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09' +
            'b95c709ee5',
        },
        {
          fingerprint: '00000003',
          path: 'm/0',
          public_key: 'deadbeef',
        },
      ],
    },
    msg: 'Derivations are encoded as legacy and taproot values',
    result: {
      legacy: [{
        key: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c7' +
          '09ee5',
        value: '00000001000000800000000001000000',
      }],
      taproot: [{
        key: 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709' +
          'ee5',
        value: '011fe2f26cd90d6b04ce4a9a4c1c5d61db08e2c04d1c72c17f3546c6dfc' +
          'fb17a45000000025600008000000080000000800000000000000000',
      }],
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    const {legacy, taproot} = encodeDerivations(args);

    deepEqual(legacy, result.legacy);
    deepEqual(taproot, result.taproot);

    return end();
  });
});
