const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const legacyTx = require('./../../transactions/legacy_transaction_components');
const transactionParts = require('./../../sighash/transaction_parts');
const witnessSharedHashes = require('./../../sighash/witness_shared_hashes');

// Test scenarios
const tests = {
  the_hashes_of_the_bip_143_native_p2wpkh_example_are_calculated: {
    args: {
      transaction: '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000',
    },
    msg: 'Shared hashes are calculated as in the BIP 143 P2WPKH example',
    result: {
      outputs: '863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5',
      prevouts: '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37',
      sequences: '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b',
    },
  },
  the_hashes_of_the_bip_143_p2sh_p2wsh_example_are_calculated: {
    args: {
      transaction: '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000',
    },
    msg: 'Shared hashes are calculated as in the BIP 143 P2SH-P2WSH example',
    result: {
      outputs: 'bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc',
      prevouts: '74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0',
      sequences: '3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const tx = legacyTx({transaction: args.transaction});

    const parts = transactionParts({transaction: tx});

    const hashes = witnessSharedHashes({parts});

    strictSame(
      {
        outputs: hashes.outputs.toString('hex'),
        prevouts: hashes.prevouts.toString('hex'),
        sequences: hashes.sequences.toString('hex'),
      },
      result,
      'Got expected shared hashes'
    );

    return;
  });
});
