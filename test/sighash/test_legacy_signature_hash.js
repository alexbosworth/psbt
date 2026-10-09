const {equal} = require('node:assert').strict;
const test = require('node:test');

const legacySignatureHash = require('./../../sighash/legacy_signature_hash');
const legacyTx = require('./../../transactions/legacy_transaction_components');
const transactionParts = require('./../../sighash/transaction_parts');

const script = '76a914' + '66'.repeat(20) + '88ac';
const transaction = '020000000301010101010101010101010101010101010101010101010101010101010101010000000000fdffffff02020202020202020202020202020202020202020202020202020202020202020100000000feffffff03030303030303030303030303030303030303030303030303030303030303030200000000ffffffff0250c3000000000000160014444444444444444444444444444444444444444460ea000000000000160014555555555555555555555555555555555555555520a10700';

// Test scenarios
const tests = {
  all_outputs_are_signed_for_the_first_input: {
    args: {script, sighash: 0x01, vin: 0},
    msg: 'All inputs and outputs are signed for the first input',
    result: '1417059794db4cacbfba00f33fe6b3d747113e7ee424fce1af2f10506d228c58',
  },
  all_outputs_are_signed: {
    args: {script, sighash: 0x01, vin: 1},
    msg: 'All inputs and outputs are signed',
    result: '373efb41f1d6c10cd842836f5d6d0862b9567e307b6f48df1ada2dc41ba71846',
  },
  no_outputs_are_signed: {
    args: {script, sighash: 0x02, vin: 1},
    msg: 'No outputs are signed, and no other input sequences',
    result: '35f56f24ba07b2d5e55d20a5eb1adcf05cdf2887a213b8d5e2d97d919def78e6',
  },
  one_output_is_signed: {
    args: {script, sighash: 0x03, vin: 1},
    msg: 'The matching output is signed, outputs before it are blanked',
    result: 'e3cdf3862b2db1a663b2d090165b9721401c533501799bf61abe74a8879912ef',
  },
  only_the_signing_input_is_signed_with_all_outputs: {
    args: {script, sighash: 0x81, vin: 1},
    msg: 'Only the signing input is signed when anyone can pay',
    result: 'f8795ee56b401a2a7253160c12b557c1c00aaeac127eeb6b94817b28faaf8938',
  },
  only_the_signing_input_is_signed_with_no_outputs: {
    args: {script, sighash: 0x82, vin: 1},
    msg: 'Only the signing input is signed with no outputs',
    result: '7e27ab6dffc2554d1af1349d16fe822855e1bdbb121e6f431912935c257d204b',
  },
  only_the_signing_input_is_signed_with_one_output: {
    args: {script, sighash: 0x83, vin: 1},
    msg: 'Only the signing input is signed with one output',
    result: '631744ae00163631f3ec716c824b5527a68fdcb138140931ed974374a1546a12',
  },
  signing_one_output_without_an_output_signs_the_number_one: {
    args: {script, sighash: 0x03, vin: 2},
    msg: 'Signing one output without an output at its index signs 1',
    result: '01' + '00'.repeat(31),
  },
  signing_one_output_alone_without_an_output_signs_the_number_one: {
    args: {script, sighash: 0x83, vin: 2},
    msg: 'Signing one output alone without an output at its index signs 1',
    result: '01' + '00'.repeat(31),
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const tx = legacyTx({transaction});

    const parts = transactionParts({transaction: tx});

    const {hash} = legacySignatureHash({...args, parts});

    equal(hash.toString('hex'), result, 'Got expected signature hash');

    return;
  });
});
