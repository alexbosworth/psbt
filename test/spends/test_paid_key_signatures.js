const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {paidKeySignatures} = require('./../../spends');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const keyA = '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f';
const keyB = '024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766';
const keyC = '02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337';
const signatures = [
  {public_key: keyC, signature: '0c'},
  {public_key: keyB, signature: '0b'},
  {public_key: keyA, signature: '0a'},
];

// Test scenarios
const tests = {
  a_key_script_takes_the_signature_of_its_key: {
    args: {script: `21${keyA}ac`, signatures},
    msg: 'A script paying to a key takes only the signature of that key',
    result: [{public_key: keyA, signature: '0a'}],
  },
  a_key_hash_script_takes_the_signature_of_a_key_with_its_hash: {
    args: {
      script: '76a91479b000887626b294a914501a4cd226b58b23598388ac',
      signatures,
    },
    msg: 'A script paying to a key hash takes the signature of that key',
    result: [{public_key: keyA, signature: '0a'}],
  },
  a_multisig_takes_the_signatures_of_its_keys: {
    args: {script: `5121${keyA}21${keyB}52ae`, signatures},
    msg: 'A multisig takes the signatures of its keys, in the same order',
    result: [
      {public_key: keyB, signature: '0b'},
      {public_key: keyA, signature: '0a'},
    ],
  },
  another_script_takes_no_signatures: {
    args: {script: '51', signatures},
    msg: 'A script that does not pay to keys takes no signatures',
    result: [],
  },
  no_script_takes_no_signatures: {
    args: {signatures},
    msg: 'Without a script there are no signatures to take',
    result: [],
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const paid = paidKeySignatures({
      script: args.script,
      signatures: args.signatures.map(n => ({
        public_key: hexAsBuffer(n.public_key),
        signature: hexAsBuffer(n.signature),
      })),
    });

    const got = paid.signatures.map(n => ({
      public_key: bufferAsHex(n.public_key),
      signature: bufferAsHex(n.signature),
    }));

    strictSame(got, result, 'Got expected signatures');

    return;
  });
});
