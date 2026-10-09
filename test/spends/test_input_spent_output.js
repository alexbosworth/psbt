const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const inputSpentOutput = require('./../../spends/input_spent_output');

const known = [{script: '51', tokens: 1}, {script: '52', tokens: 2}];
const supplied = [{script: '53', tokens: 3}];

// Test scenarios
const tests = {
  a_supplied_funding_transaction_is_used_first: {
    args: {
      known,
      supplied,
      vout: 0,
      witness_utxo: {script_pub: '54', tokens: 4},
    },
    msg: 'The output of a supplied funding transaction is used first',
    result: {script: '53', tokens: 3},
  },
  a_supplied_funding_transaction_needs_the_spent_output: {
    args: {supplied, vout: 1},
    err: 'ExpectedSpentOutputInSpendingTransaction',
    msg: 'A supplied funding transaction must have the spent output',
  },
  a_witness_utxo_is_used_next: {
    args: {known, vout: 1, witness_utxo: {script_pub: '54', tokens: 4}},
    msg: 'A witness UTXO is used when no funding transaction is supplied',
    result: {script: '54', tokens: 4},
  },
  a_known_funding_transaction_is_used_last: {
    args: {known, vout: 1},
    msg: 'A funding transaction already in the PSBT is used last',
    result: {script: '52', tokens: 2},
  },
  no_output_is_known_without_funding_records: {
    args: {vout: 0},
    msg: 'No output is known without funding records',
    result: {},
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, () => {
    if (!!err) {
      throws(() => inputSpentOutput(args), new Error(err));

      return;
    }

    strictSame(inputSpentOutput(args), result, 'Got expected result');

    return;
  });
});
