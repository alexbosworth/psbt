const {deepStrictEqual} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {legacyTransactionComponents} = require('./../../transactions');

const id = '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858';
const outpoint = Buffer.from(id, 'hex').reverse().toString('hex') + '01000000';
const output = '70aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d';
const script = '0014d85c2b71d0060b09c9886aeb815e50991dda124d';

// Test scenarios
const tests = {
  a_transaction_with_an_input_and_an_output_is_read: {
    args: {transaction: `0200000001${outpoint}00feffffff01${output}64000000`},
    msg: 'A transaction with an input and an output is read',
    result: {
      inputs: [{id, script: '', sequence: 4294967294, vout: 1}],
      locktime: 100,
      outputs: [{script, tokens: 149990000}],
      version: 2,
    },
  },
  a_transaction_without_inputs_is_read_without_a_witness_marker: {
    args: {transaction: `020000000001${output}00000000`},
    msg: 'A transaction without inputs is not read as a SegWit transaction',
    result: {
      inputs: [],
      locktime: 0,
      outputs: [{script, tokens: 149990000}],
      version: 2,
    },
  },
  a_transaction_cut_short_is_rejected: {
    args: {transaction: '020000'},
    err: 'ExpectedAdditionalTransactionDataToParse',
    msg: 'A transaction that is cut short is rejected',
  },
  an_input_count_beyond_the_data_is_rejected: {
    args: {transaction: `0200000005${outpoint}00feffffff01${output}00000000`},
    err: 'UnexpectedInputCountForTransactionDataLength',
    msg: 'An input count that the data cannot hold is rejected',
  },
  an_output_count_beyond_the_data_is_rejected: {
    args: {transaction: `020000000005${output}00000000`},
    err: 'UnexpectedOutputCountForTransactionDataLength',
    msg: 'An output count that the data cannot hold is rejected',
  },
  an_output_value_beyond_the_safe_number_limit_is_rejected: {
    args: {transaction: '020000000001ffffffffffffffff0000000000'},
    err: 'UnexpectedOutputValueInTransaction',
    msg: 'An output value that cannot be represented as a number is rejected',
  },
  data_after_the_transaction_is_rejected: {
    args: {transaction: `020000000001${output}0000000000`},
    err: 'UnexpectedDataAfterTransaction',
    msg: 'Data after the end of the transaction is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => legacyTransactionComponents(args), new Error(err));

      return end();
    }

    deepStrictEqual(legacyTransactionComponents(args), result);

    return end();
  });
});
