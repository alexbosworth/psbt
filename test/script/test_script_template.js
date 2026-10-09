const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {scriptTemplate} = require('./../../script');

const asBuffer = hex => Buffer.from(hex, 'hex');
const hash = '11'.repeat(20);
const key1 = '02'.repeat(33);
const key2 = '03'.repeat(33);

// Test scenarios
const tests = {
  a_script_paying_to_a_key_has_the_key: {
    args: {script: `21${key1}ac`},
    msg: 'A script paying to a public key has that key',
    result: {key: asBuffer(key1)},
  },
  a_script_paying_to_a_key_hash_has_the_hash: {
    args: {script: `76a914${hash}88ac`},
    msg: 'A script paying to a public key hash has that hash',
    result: {hash: asBuffer(hash)},
  },
  a_multisig_script_has_its_keys: {
    args: {script: `5221${key1}21${key2}52ae`},
    msg: 'A multisig script has its keys and the signatures it requires',
    result: {keys: [asBuffer(key1), asBuffer(key2)], required: 2},
  },
  a_one_of_two_multisig_script_has_its_keys: {
    args: {script: `5121${key1}21${key2}52ae`},
    msg: 'A one of two multisig script requires one signature',
    result: {keys: [asBuffer(key1), asBuffer(key2)], required: 1},
  },
  a_script_dropping_a_key_has_no_keys: {
    args: {script: `21${key1}7521${key2}ac`},
    msg: 'A script that pushes and drops a key has no keys',
    result: {},
  },
  a_script_checking_a_number_signature_has_no_keys: {
    args: {script: '51ac'},
    msg: 'A script checking a signature with a number has no keys',
    result: {},
  },
  a_key_hash_script_with_a_short_hash_has_no_keys: {
    args: {script: `76a913${'11'.repeat(19)}88ac`},
    msg: 'A key hash script with a hash that is too short has no keys',
    result: {},
  },
  a_key_hash_script_with_other_op_codes_has_no_keys: {
    args: {script: `76a914${hash}87ac`},
    msg: 'A key hash script with other op codes has no keys',
    result: {},
  },
  a_script_with_a_code_separator_has_no_keys: {
    args: {script: `ab21${key1}ac`},
    msg: 'A script with a code separator has no keys',
    result: {},
  },
  a_multisig_requiring_more_signatures_than_keys_has_no_keys: {
    args: {script: `5321${key1}21${key2}52ae`},
    msg: 'A multisig requiring more signatures than keys has no keys',
    result: {},
  },
  a_multisig_requiring_no_signatures_has_no_keys: {
    args: {script: `0021${key1}51ae`},
    msg: 'A multisig requiring no signatures has no keys',
    result: {},
  },
  a_multisig_with_a_wrong_key_count_has_no_keys: {
    args: {script: `5121${key1}21${key2}53ae`},
    msg: 'A multisig with a key count that is not its key count has no keys',
    result: {},
  },
  a_multisig_without_a_key_count_has_no_keys: {
    args: {script: `5121${key1}21${key2}ae`},
    msg: 'A multisig without a number for its key count has no keys',
    result: {},
  },
  a_multisig_with_an_op_code_among_its_keys_has_no_keys: {
    args: {script: `5121${key1}7521${key2}52ae`},
    msg: 'A multisig with an op code among its keys has no keys',
    result: {},
  },
  a_script_that_cannot_be_parsed_has_no_keys: {
    args: {script: '4c'},
    msg: 'A script that cannot be parsed has no keys',
    result: {},
  },
  an_empty_script_has_no_keys: {
    args: {script: ''},
    msg: 'An empty script has no keys',
    result: {},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(scriptTemplate(args), result, 'Got expected script template');

    return;
  });
});
