const {equal} = require('node:assert').strict;
const test = require('node:test');

const legacyTx = require('./../../transactions/legacy_transaction_components');
const transactionParts = require('./../../sighash/transaction_parts');
const v0SignatureHash = require('./../../sighash/v0_signature_hash');
const witnessSharedHashes = require('./../../sighash/witness_shared_hashes');

// BIP 143 native P2WPKH example
const p2wpkhTx = '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000';

// BIP 143 P2SH-P2WSH example
const nestedTx = '010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000';
const nestedScript = '56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae';

// A transaction with more inputs than outputs
const singleScript = '76a914' + '66'.repeat(20) + '88ac';
const singleTx = '020000000301010101010101010101010101010101010101010101010101010101010101010000000000fdffffff02020202020202020202020202020202020202020202020202020202020202020100000000feffffff03030303030303030303030303030303030303030303030303030303030303030200000000ffffffff0250c3000000000000160014444444444444444444444444444444444444444460ea000000000000160014555555555555555555555555555555555555555520a10700';

// Test scenarios
const tests = {
  a_native_witness_public_key_hash_input_is_hashed: {
    args: {
      script: '76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac',
      sighash: 0x01,
      tokens: 600000000,
      transaction: p2wpkhTx,
      vin: 1,
    },
    msg: 'The BIP 143 native P2WPKH example is hashed',
    result: 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670',
  },
  all_outputs_are_signed: {
    args: {
      script: nestedScript,
      sighash: 0x01,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed signing all outputs',
    result: '185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c',
  },
  no_outputs_are_signed: {
    args: {
      script: nestedScript,
      sighash: 0x02,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed signing no outputs',
    result: 'e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36',
  },
  one_output_is_signed: {
    args: {
      script: nestedScript,
      sighash: 0x03,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed signing one output',
    result: '1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea',
  },
  anyone_can_pay_with_all_outputs: {
    args: {
      script: nestedScript,
      sighash: 0x81,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed with all outputs, any inputs',
    result: '2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e',
  },
  anyone_can_pay_with_no_outputs: {
    args: {
      script: nestedScript,
      sighash: 0x82,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed with no outputs, any inputs',
    result: '781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a',
  },
  anyone_can_pay_with_one_output: {
    args: {
      script: nestedScript,
      sighash: 0x83,
      tokens: 987654321,
      transaction: nestedTx,
      vin: 0,
    },
    msg: 'The BIP 143 nested example is hashed with one output, any inputs',
    result: '511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b',
  },
  one_output_without_a_matching_output_signs_no_outputs: {
    args: {
      script: singleScript,
      sighash: 0x03,
      tokens: 70000,
      transaction: singleTx,
      vin: 2,
    },
    msg: 'Signing one output without a matching output commits to no outputs',
    result: 'c90d5d646a6d06d6c9534b9d720b3ffb91e924704361469119c9550b27901252',
  },
  anyone_can_pay_without_a_matching_output: {
    args: {
      script: singleScript,
      sighash: 0x83,
      tokens: 70000,
      transaction: singleTx,
      vin: 2,
    },
    msg: 'Anyone can pay without a matching output commits to no outputs',
    result: '22bba6eed23229c8fc579ac39b5e3682e23a5ba023caa471c69aa9b7e65bfc6a',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const tx = legacyTx({transaction: args.transaction});

    const parts = transactionParts({transaction: tx});

    const {hash} = v0SignatureHash({
      parts,
      hashes: witnessSharedHashes({parts}),
      script: args.script,
      sighash: args.sighash,
      tokens: args.tokens,
      vin: args.vin,
    });

    equal(hash.toString('hex'), result, 'Got expected signature hash');

    return;
  });
});
