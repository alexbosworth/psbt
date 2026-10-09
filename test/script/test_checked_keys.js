const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {checkedKeys} = require('./../../script');

const a = '02' + '11'.repeat(32);
const b = '02' + '22'.repeat(32);
const c = '02' + '33'.repeat(32);
const hash = '44'.repeat(20);
const push = key => `21${key}`;

// Test scenarios
const tests = {
  a_key_pushed_before_a_signature_check_is_checked: {
    args: {script: `${push(a)}ac`},
    msg: 'A key pushed right before a signature check is checked',
    result: {hashes: [], keys: [a]},
  },
  a_key_hash_check_checks_the_key_of_the_hash: {
    args: {script: `76a914${hash}88ac`},
    msg: 'A key hash check checks the key of the hash',
    result: {hashes: [hash], keys: []},
  },
  the_keys_of_a_multisig_check_are_checked: {
    args: {script: `52${push(a)}${push(b)}${push(c)}53ae`},
    msg: 'The keys of a multisig check are checked',
    result: {hashes: [], keys: [a, b, c]},
  },
  a_key_that_is_only_data_is_not_checked: {
    args: {script: `${push(a)}75${push(b)}ac`},
    msg: 'A key that a script only has as data is not checked',
    result: {hashes: [], keys: [b]},
  },
  keys_of_verified_signature_checks_are_checked: {
    args: {script: `${push(a)}ad${push(b)}ac`},
    msg: 'Keys of signature checks that verify are checked',
    result: {hashes: [], keys: [a, b]},
  },
  keys_checked_in_branches_are_checked: {
    args: {script: `63${push(a)}ac67${push(b)}ac68`},
    msg: 'Keys checked in the branches of a script are checked',
    result: {hashes: [], keys: [a, b]},
  },
  a_key_checked_before_other_conditions_is_checked: {
    args: {script: `${push(a)}ac736460b268`},
    msg: 'A key checked before other conditions is checked',
    result: {hashes: [], keys: [a]},
  },
  keys_of_a_verified_multisig_check_are_checked: {
    args: {script: `51${push(a)}51af${push(b)}ac`},
    msg: 'Keys of a multisig check that verifies are checked',
    result: {hashes: [], keys: [a, b]},
  },
  a_multisig_check_without_a_count_checks_no_keys: {
    args: {script: `${push(a)}${push(b)}ae`},
    msg: 'A multisig check without a count of keys checks no keys',
    result: {hashes: [], keys: []},
  },
  a_multisig_check_without_room_for_a_required_count_checks_no_keys: {
    args: {script: `${push(a)}51ae`},
    msg: 'A multisig check without a required count checks no keys',
    result: {hashes: [], keys: []},
  },
  a_multisig_check_with_data_for_a_required_count_checks_no_keys: {
    args: {script: `${push(c)}${push(a)}51ae`},
    msg: 'A multisig check with data for a required count checks no keys',
    result: {hashes: [], keys: []},
  },
  a_multisig_check_of_elements_that_are_not_keys_checks_no_keys: {
    args: {script: `5175${push(a)}52ae`},
    msg: 'A multisig check of elements that are not all keys checks none',
    result: {hashes: [], keys: []},
  },
  a_multisig_check_requiring_too_many_signatures_checks_no_keys: {
    args: {script: `53${push(a)}${push(b)}52ae`},
    msg: 'A multisig check requiring more signatures than keys checks none',
    result: {hashes: [], keys: []},
  },
  a_script_that_cannot_be_parsed_checks_no_keys: {
    args: {script: '4c'},
    msg: 'A script that cannot be parsed checks no keys',
    result: {hashes: [], keys: []},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const {hashes, keys} = checkedKeys(args);

    const got = {
      hashes: hashes.map(n => n.toString('hex')),
      keys: keys.map(n => n.toString('hex')),
    };

    strictSame(got, result, 'Got expected checked keys');

    return;
  });
});
