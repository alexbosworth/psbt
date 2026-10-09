const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const hash160 = require('./../../spends/hash160');
const scriptSigningKeys = require('./../../spends/script_signing_keys');

const otherKey = '03' + '33'.repeat(32);
const publicKey = '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f';
const uncompressedKey = '04' + '44'.repeat(64);

const key = {public_key: Buffer.from(publicKey, 'hex')};
const keyHash = hash160({data: key.public_key}).toString('hex');
const uncompressed = {public_key: Buffer.from(uncompressedKey, 'hex')};
const uncompressedHash = hash160({data: uncompressed.public_key});

// Test scenarios
const tests = {
  a_key_is_found_by_its_public_key: {
    args: {script: `21${publicKey}ac`},
    msg: 'A key is found when the script pays to its public key',
    result: [publicKey],
  },
  a_key_is_found_by_its_public_key_hash: {
    args: {script: `76a914${keyHash}88ac`},
    msg: 'A key is found when the script pays to its public key hash',
    result: [publicKey],
  },
  a_key_is_found_in_a_multisig: {
    args: {script: `5221${otherKey}21${publicKey}52ae`},
    msg: 'A key is found when it is a key of a multisig script',
    result: [publicKey],
  },
  a_key_found_twice_in_a_multisig_is_returned_once: {
    args: {script: `5221${publicKey}21${publicKey}52ae`},
    msg: 'A key that is in a multisig twice is returned once',
    result: [publicKey],
  },
  a_key_that_is_pushed_and_dropped_is_not_found: {
    args: {script: `21${publicKey}7521${otherKey}ac`},
    msg: 'A key that a script pushes without checking it is not found',
    result: [],
  },
  a_key_hash_pushed_outside_of_a_key_hash_script_is_not_found: {
    args: {script: `a914${keyHash}87`},
    msg: 'A key hash outside of a pay to key hash script is not found',
    result: [],
  },
  a_key_hash_in_the_place_of_a_multisig_key_is_not_found: {
    args: {script: `5114${keyHash}51ae`},
    msg: 'A key hash in the place of a multisig key is not found',
    result: [],
  },
  a_script_with_a_code_separator_has_no_keys: {
    args: {script: `ab21${publicKey}ac`},
    msg: 'A script with a code separator has no signing keys',
    result: [],
  },
  a_script_that_cannot_be_parsed_has_no_keys: {
    args: {script: 'ab4c'},
    msg: 'A script that cannot be parsed has no keys',
    result: [],
  },
  an_uncompressed_key_signs_a_legacy_script: {
    args: {script: `41${uncompressedKey}ac`},
    msg: 'An uncompressed key is found for a legacy script',
    result: [uncompressedKey],
  },
  an_uncompressed_key_does_not_sign_a_witness_script: {
    args: {is_witness: true, script: `41${uncompressedKey}ac`},
    msg: 'An uncompressed key is not found for a witness script',
    result: [],
  },
  a_compressed_key_signs_a_witness_script: {
    args: {
      is_witness: true,
      script: `5241${uncompressedKey}21${publicKey}52ae`,
    },
    msg: 'Only compressed keys are found for a witness script',
    result: [publicKey],
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const keys = new Map([
      [publicKey, key],
      [keyHash, key],
      [uncompressedKey, uncompressed],
      [uncompressedHash.toString('hex'), uncompressed],
    ]);

    const found = scriptSigningKeys({
      keys,
      is_witness: args.is_witness,
      script: args.script,
    });

    strictSame(
      found.keys.map(n => n.public_key.toString('hex')),
      result,
      'Got expected keys'
    );

    return;
  });
});
