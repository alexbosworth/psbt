const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {taprootOutputKey} = require('./../../utxos');

// Test scenarios
const tests = {
  a_taproot_output_script_has_an_output_key: {
    args: {script: `5120${'77'.repeat(32)}`},
    msg: 'A taproot output script has an output key',
    result: {output_key: '77'.repeat(32)},
  },
  no_output_script_has_no_output_key: {
    args: {},
    msg: 'There is no output key without an output script',
    result: {},
  },
  a_version_0_witness_program_has_no_output_key: {
    args: {script: `0020${'77'.repeat(32)}`},
    msg: 'A version 0 witness program of 32 bytes has no output key',
    result: {},
  },
  a_short_version_1_witness_program_has_no_output_key: {
    args: {script: `5114${'77'.repeat(20)}`},
    msg: 'A version 1 witness program that is not 32 bytes has no output key',
    result: {},
  },
  a_legacy_output_script_has_no_output_key: {
    args: {script: `76a914${'77'.repeat(20)}88ac`},
    msg: 'A legacy output script has no output key',
    result: {},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(taprootOutputKey(args), result, 'Got expected output key');

    return;
  });
});
