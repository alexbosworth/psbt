const {deepEqual} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {multisigDetails} = require('./../../script');

const key1 = '21' + '02'.repeat(33);
const key2 = '21' + '03'.repeat(33);
const redeem = '51' + key1 + key2 + '52ae';
const signature = '30'.repeat(70) + '01';

// Test scenarios
const tests = {
  a_missing_script_returns_no_details: {
    args: {},
    msg: 'A missing script returns no details',
    result: {},
  },
  a_script_ending_in_an_op_code_returns_no_details: {
    args: {script: '00'},
    msg: 'A script ending in an op code returns no details',
    result: {},
  },
  a_script_that_is_not_multisig_returns_no_details: {
    args: {script: '00' + '47' + signature + '03aaaaaa'},
    msg: 'A script that is not a multisig spend returns no details',
    result: {},
  },
  a_partially_signed_multisig_script_is_rejected: {
    args: {script: '00' + '47' + signature + '47' + redeem},
    err: 'PartialKeySigningNotSupported',
    msg: 'A partially signed multisig script is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => multisigDetails(args), new Error(err));

      return end();
    }

    deepEqual(multisigDetails(args), result);

    return end();
  });
});
