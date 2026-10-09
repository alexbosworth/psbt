const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const inputSpend = require('./../../spends/input_spend');

const keyHash = '9c4942a9f2efe4fb66fb2021c8e1b5e03b257cba';
const multisig = '5121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae';
const nestedWitness = '0020' + '11'.repeat(32);
const p2pkh = `76a914${keyHash}88ac`;
const p2sh = 'a91421b6ec25482b95dd33fd93ff7680a71d1660a7c187';

// Test scenarios
const tests = {
  an_input_without_a_utxo_or_scripts_is_not_signed: {
    args: {input: {}, spent: {}},
    msg: 'An input without a UTXO or scripts is not signed',
    result: {},
  },
  a_legacy_redeem_script_without_a_utxo_is_a_legacy_spend: {
    args: {input: {redeem_script: multisig}, spent: {}},
    msg: 'A legacy redeem script without a UTXO is a legacy spend',
    result: {is_witness: false, script: multisig},
  },
  a_nested_witness_redeem_script_without_a_utxo_is_a_witness_spend: {
    args: {input: {redeem_script: `0014${keyHash}`}, spent: {}},
    msg: 'A nested witness redeem script without a UTXO is a witness spend',
    result: {is_witness: true, script: p2pkh},
  },
  a_witness_script_without_a_utxo_is_a_witness_spend: {
    args: {input: {witness_script: multisig}, spent: {}},
    msg: 'A witness script without a UTXO is a witness spend',
    result: {is_witness: true, script: multisig},
  },
  a_witness_public_key_hash_output_is_a_witness_spend: {
    args: {input: {}, spent: {script: `0014${keyHash}`, tokens: 1000}},
    msg: 'A witness public key hash output is a witness spend',
    result: {is_witness: true, script: p2pkh, tokens: 1000},
  },
  a_p2sh_output_without_a_redeem_script_is_not_signed: {
    args: {input: {}, spent: {script: p2sh, tokens: 1}},
    msg: 'A P2SH output without a redeem script is not signed',
    result: {},
  },
  a_nested_witness_script_output_is_a_witness_spend: {
    args: {
      input: {redeem_script: nestedWitness, witness_script: multisig},
      spent: {script: p2sh, tokens: 1},
    },
    msg: 'A nested witness script output is a witness spend',
    result: {is_witness: true, script: multisig, tokens: 1},
  },
  a_witness_script_hash_output_without_a_witness_script_is_not_signed: {
    args: {input: {}, spent: {script: nestedWitness, tokens: 1}},
    msg: 'A witness script hash output without a witness script is not signed',
    result: {},
  },
  a_legacy_output_is_a_legacy_spend: {
    args: {input: {}, spent: {script: p2pkh, tokens: 2000}},
    msg: 'A legacy output is a legacy spend of its script',
    result: {is_witness: false, script: p2pkh, tokens: 2000},
  },
  a_legacy_redeem_script_of_a_p2sh_output_is_a_legacy_spend: {
    args: {
      input: {redeem_script: multisig},
      spent: {script: p2sh, tokens: 3000},
    },
    msg: 'A legacy redeem script of a P2SH output is a legacy spend',
    result: {is_witness: false, script: multisig, tokens: 3000},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(inputSpend(args), result, 'Got expected spend');

    return;
  });
});
