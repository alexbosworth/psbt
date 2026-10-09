const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {legacyTransactionComponents} = require('./../../transactions');
const {taprootSharedHashes} = require('./../../sighash');
const {taprootSignatureHash} = require('./../../sighash');
const {transactionParts} = require('./../../sighash');

const spent = [
  {script: '5120' + '44'.repeat(32), tokens: 50000},
  {script: '5120' + '55'.repeat(32), tokens: 30000},
];
const transaction = '020000000211111111111111111111111111111111111111111111111111111111111111110100000000fdffffff22222222222222222222222222222222222222222222222222222222222222220000000000ffffffff017011010000000000160014333333333333333333333333333333333333333300350c00';

// Test scenarios, with signature hashes from bitcoinjs-lib
const tests = {
  the_default_sighash_type_signs_everything: {
    args: {sighash: 0x00, vin: 0},
    msg: 'The default sighash type signs all of the inputs and outputs',
    result: 'd429c97b9fc1e3d334cbaf8c6d8c86da8b2c27df2d1df61e6265d1f24f8b2839',
  },
  sighash_all_signs_everything_with_its_own_type: {
    args: {sighash: 0x01, vin: 0},
    msg: 'Sighash all signs all of the inputs and outputs',
    result: 'c8471666a9866a8947c2baa2b5d61e2519bee432e8e12a9250601febd9713874',
  },
  sighash_none_signs_no_outputs: {
    args: {sighash: 0x02, vin: 0},
    msg: 'Sighash none signs all of the inputs and no outputs',
    result: 'e98490f829ea7b54d64af04e92d9290faa847fa1fff9ff84efaec645d93ba4ba',
  },
  sighash_single_signs_the_output_of_the_input: {
    args: {sighash: 0x03, vin: 0},
    msg: 'Sighash single signs the output at the index of the input',
    result: '4e6dd970485ed994651f4dc8d620faa00caef373c2e50c83bd31fef1e0595f97',
  },
  anyone_can_pay_signs_only_its_input: {
    args: {sighash: 0x81, vin: 0},
    msg: 'Anyone can pay signs only its input, with all outputs',
    result: 'd12dc0ccb062bb32047020e2b038ccbf486e64a9c742ccb05577c30302492333',
  },
  anyone_can_pay_with_no_outputs_signs_only_its_input: {
    args: {sighash: 0x82, vin: 0},
    msg: 'Anyone can pay with sighash none signs only its input',
    result: '982af6b0233a67ede2e6086a2ca3f9876ff5f3cc1da9fedef8325f49472abf51',
  },
  anyone_can_pay_with_one_output_signs_its_input_and_output: {
    args: {sighash: 0x83, vin: 0},
    msg: 'Anyone can pay with sighash single signs its input and output',
    result: '63be868326304a3b47ccf01f254394b22dfa17ec571d1f92f1b02c4d8970d656',
  },
  a_later_input_signs_its_index: {
    args: {sighash: 0x00, vin: 1},
    msg: 'A later input signs its own index',
    result: 'a70812c49b9f0c39ecf42189799097e4c74a300a83e0f85f574b032155041cc2',
  },
  a_later_input_signs_no_outputs: {
    args: {sighash: 0x02, vin: 1},
    msg: 'A later input with sighash none signs no outputs',
    result: 'a185393e8540a014527fb179aa6006d4e8ee02cd11cde97206b3d9a29eb615b3',
  },
  a_later_input_alone_signs_no_outputs: {
    args: {is_unknown_other: true, sighash: 0x82, vin: 1},
    msg: 'A later input signing alone needs only the output it spends',
    result: 'f444796b854de7c4aad752408e324f2f576cd4a03122280a0de25af54335d0b0',
  },
  one_output_needs_an_output_at_the_input_index: {
    args: {sighash: 0x03, vin: 1},
    err: 'ExpectedOutputForInputSigningWithSigHashSingle',
    msg: 'Signing one output needs an output at the index of the input',
  },
  every_input_needs_the_outputs_that_inputs_spend: {
    args: {is_unknown_other: true, sighash: 0x01, vin: 1},
    err: 'ExpectedSpentOutputsOfInputsToHashTaprootSignature',
    msg: 'Signing every input needs the outputs that every input spends',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, () => {
    const tx = legacyTransactionComponents({transaction});

    const parts = transactionParts({transaction: tx});

    // An unknown output of another input leaves out the spent output hashes
    const outputs = args.is_unknown_other ? [{}, spent[1]] : spent;

    const hashes = taprootSharedHashes({parts, spent: outputs});

    const {sighash, vin} = args;

    const signing = {hashes, parts, sighash, vin, spent: spent[vin]};

    if (!!err) {
      throws(() => taprootSignatureHash(signing), new Error(err));

      return;
    }

    const {hash} = taprootSignatureHash(signing);

    equal(hash.toString('hex'), result, 'Got expected signature hash');

    return;
  });
});
