const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {spentOutputs} = require('./../../spends');

const id = '1416700a618066598001227827d3eb808138107fc74d445d5df08be4a7db18b9';
const p2pkh = '76a9149c4942a9f2efe4fb66fb2021c8e1b5e03b257cba88ac';
const p2sh = 'a91421b6ec25482b95dd33fd93ff7680a71d1660a7c187';
const previousTx = '020000000109090909090909090909090909090909090909090909090909090909090909090000000000ffffffff03e8030000000000001600149c4942a9f2efe4fb66fb2021c8e1b5e03b257cbad0070000000000001976a9149c4942a9f2efe4fb66fb2021c8e1b5e03b257cba88acb80b00000000000017a91421b6ec25482b95dd33fd93ff7680a71d1660a7c18700000000';
const witnessUtxo = {script_pub: '0014' + '11'.repeat(20), tokens: 5000};

// Test scenarios
const tests = {
  an_input_without_a_utxo_has_no_known_spent_output: {
    args: {inputs: [{}], transaction: {inputs: [{id, vout: 0}]}},
    msg: 'An input without a UTXO has no known spent output',
    result: {spent: [{}]},
  },
  the_witness_utxo_is_the_spent_output: {
    args: {
      inputs: [{non_witness_utxo: previousTx, witness_utxo: witnessUtxo}],
      transaction: {inputs: [{id, vout: 1}]},
    },
    msg: 'The witness UTXO of an input is the output that it spends',
    result: {spent: [{script: witnessUtxo.script_pub, tokens: 5000}]},
  },
  the_spent_output_of_a_full_utxo_is_found_by_its_index: {
    args: {
      inputs: [{non_witness_utxo: previousTx}],
      transaction: {inputs: [{id, vout: 1}]},
    },
    msg: 'The spent output of a full UTXO is found by its index',
    result: {spent: [{script: p2pkh, tokens: 2000}]},
  },
  inputs_spending_from_the_same_transaction_share_its_outputs: {
    args: {
      inputs: [{non_witness_utxo: previousTx}, {non_witness_utxo: previousTx}],
      transaction: {inputs: [{id, vout: 1}, {id, vout: 2}]},
    },
    msg: 'Inputs spending from the same transaction get their own outputs',
    result: {
      spent: [{script: p2pkh, tokens: 2000}, {script: p2sh, tokens: 3000}],
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    strictSame(spentOutputs(args), result, 'Got expected spent outputs');

    return;
  });
});
