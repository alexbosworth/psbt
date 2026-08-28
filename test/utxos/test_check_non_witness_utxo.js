const test = require('node:test');
const {throws} = require('node:assert').strict;

const {checkNonWitnessUtxo} = require('./../../utxos');

const utxo = Buffer.from('010000000101010101010101010101010101010101010101010101010101010101010101010000000000ffffffff05e8030000000000001600141111111111111111111111111111111111111111e80300000000000016a9131111111111111111111111111111111111111187e80300000000000017a9141111111111111111111111111111111111111111ace80300000000000018a91411111111111111111111111111111111111111118751e80300000000000017a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8700000000', 'hex');

// Test scenarios
const tests = {
  a_matching_p2sh_output_passes_the_check: {
    args: {utxo, hash: Buffer.alloc(20, 0xaa), script: Buffer.from('00', 'hex')},
    msg: 'A matching p2sh output among non-p2sh outputs passes the check',
  },
  a_redeem_script_hash_is_expected: {
    args: {},
    err: 'ExpectedNonWitnessRedeemScriptHashBuffer',
    msg: 'A redeem script hash is expected',
  },
  a_redeem_script_is_expected: {
    args: {hash: Buffer.alloc(20, 0xaa)},
    err: 'ExpectedNonWitnessRedeemScriptBuffer',
    msg: 'A redeem script is expected',
  },
  a_utxo_is_expected: {
    args: {hash: Buffer.alloc(20, 0xaa), script: Buffer.from('00', 'hex')},
    err: 'ExpectedNonWitnessUtxoBuffer',
    msg: 'A utxo is expected',
  },
  a_utxo_without_a_matching_output_is_rejected: {
    args: {utxo, hash: Buffer.alloc(20, 0xbb), script: Buffer.from('00', 'hex')},
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A utxo without a matching p2sh output is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => checkNonWitnessUtxo(args), new Error(err));

      return end();
    }

    checkNonWitnessUtxo(args);

    return end();
  });
});
