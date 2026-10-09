const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {inputSighashType} = require('./../../spends');

const ecdsa = `30440220${'11'.repeat(32)}0220${'22'.repeat(32)}`;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const keyA = `02${'02'.repeat(33)}`;
const keyB = `02${'03'.repeat(33)}`;
const schnorr = '9a'.repeat(64);
const scriptSig = `14${'cc'.repeat(64)}`;

// Test scenarios
const tests = {
  an_input_with_a_sighash_type_gets_no_other_type: {
    args: {
      pairs: [
        {type: keyA, value: `${ecdsa}83`},
        {type: '03', value: '01000000'},
      ],
    },
    msg: 'An input that has a sighash type gets no other sighash type',
    result: {},
  },
  an_input_without_signatures_gets_no_sighash_type: {
    args: {pairs: [{type: '04', value: `0014${'77'.repeat(20)}`}]},
    msg: 'An input without signatures gets no sighash type',
    result: {},
  },
  signatures_sharing_a_sighash_type_set_it: {
    args: {
      pairs: [
        {type: keyA, value: `${ecdsa}83`},
        {type: keyB, value: `${ecdsa}83`},
        {type: '04', value: `0014${'77'.repeat(20)}`},
      ],
    },
    msg: 'Signatures that share a sighash type give the input that type',
    result: {sighash_type: 131},
  },
  signatures_with_different_sighash_types_set_none: {
    args: {
      pairs: [
        {type: keyA, value: `${ecdsa}01`},
        {type: keyB, value: `${ecdsa}83`},
      ],
    },
    msg: 'Signatures with different sighash types give the input none',
    result: {},
  },
  a_taproot_signature_of_another_type_sets_none: {
    args: {
      pairs: [
        {type: keyA, value: `${ecdsa}01`},
        {type: '13', value: schnorr},
      ],
    },
    msg: 'A taproot signature of another sighash type means no type is set',
    result: {},
  },
  taproot_signatures_sharing_a_sighash_type_set_it: {
    args: {
      pairs: [
        {type: '13', value: `${schnorr}83`},
        {type: scriptSig, value: `${schnorr}83`},
      ],
    },
    msg: 'Taproot signatures that share a sighash type give the input it',
    result: {sighash_type: 131},
  },
  a_64_byte_taproot_signature_has_the_default_type: {
    args: {pairs: [{type: '13', value: schnorr}]},
    msg: 'A 64 byte taproot signature has the default sighash type',
    result: {sighash_type: 0},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const pairs = args.pairs.map(n => ({
      type: hexAsBuffer(n.type),
      value: hexAsBuffer(n.value),
    }));

    strictSame(inputSighashType({pairs}), result, 'Got expected result');

    return;
  });
});
