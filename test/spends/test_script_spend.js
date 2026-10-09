const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const scriptSpend = require('./../../spends/script_spend');

const keyHash = '9c4942a9f2efe4fb66fb2021c8e1b5e03b257cba';
const witness = '5121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae';

// Test scenarios
const tests = {
  a_legacy_script_is_signed_as_itself: {
    args: {script: witness},
    msg: 'A script that is not a witness program is signed as a legacy script',
    result: {is_witness: false, script: witness},
  },
  a_push_too_short_for_a_program_is_a_legacy_script: {
    args: {script: '0001ab'},
    msg: 'A push that is too short for a witness program is a legacy script',
    result: {is_witness: false, script: '0001ab'},
  },
  a_push_too_long_for_a_program_is_a_legacy_script: {
    args: {script: '5129' + '11'.repeat(41)},
    msg: 'A push that is too long for a witness program is a legacy script',
    result: {is_witness: false, script: '5129' + '11'.repeat(41)},
  },
  a_public_key_hash_program_is_signed_as_a_p2pkh_script: {
    args: {script: `0014${keyHash}`},
    msg: 'A public key hash program is signed as a P2PKH script',
    result: {is_witness: true, script: `76a914${keyHash}88ac`},
  },
  a_script_hash_program_is_signed_with_its_witness_script: {
    args: {witness, script: '0020' + '11'.repeat(32)},
    msg: 'A script hash program is signed with its witness script',
    result: {is_witness: true, script: witness},
  },
  a_script_hash_program_without_a_witness_script_is_not_signed: {
    args: {script: '0020' + '11'.repeat(32)},
    msg: 'A script hash program without a witness script is not signed',
    result: {},
  },
  a_later_version_program_is_not_signed: {
    args: {script: '5120' + '11'.repeat(32)},
    msg: 'A program of a later witness version is not signed',
    result: {},
  },
  a_version_zero_program_of_another_length_is_not_signed: {
    args: {script: '0019' + '11'.repeat(25)},
    msg: 'A version 0 program of another length is not signed',
    result: {},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(scriptSpend(args), result, 'Got expected spend');

    return;
  });
});
