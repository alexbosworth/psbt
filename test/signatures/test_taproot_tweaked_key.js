const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {taprootTweakedKey} = require('./../../signatures');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// Test scenarios
const tests = {
  a_key_is_tweaked_without_a_script_tree: {
    args: {
      private_key: '2c6ba77e9184c5b6c6215f84ef0e00558884dec7d23a027f0573d11bf77aff46',
    },
    msg: 'A key with an even public key is tweaked without a script tree',
    result: {
      output_key: '9ccc1cfb098556122565534573f28f154e06805cad2ccc7d8fc69dd3e002500f',
      private_key: 'ee1b0034be8ba6d906648c554a5ac41491682eb7a0c3cd19d92688a64b46e957',
    },
  },
  a_key_is_tweaked_with_a_merkle_root: {
    args: {
      merkle_root: '5b'.repeat(32),
      private_key: '2c6ba77e9184c5b6c6215f84ef0e00558884dec7d23a027f0573d11bf77aff46',
    },
    msg: 'A key with an even public key is tweaked with a merkle root',
    result: {
      output_key: 'dbb8de44d1c58fdd98bfb979e1ab3a00b7304c72c2122cf8c0ad00ae1705c23a',
      private_key: 'abaedec3a96b4e0bc4900acb9a01edc06c00f6d311305c519206b6bce72b8768',
    },
  },
  an_odd_key_is_negated_and_tweaked: {
    args: {
      private_key: '68cfa8072f964148cb0dcedae42bbab417872739afef513314b29619ff3de9c4',
    },
    msg: 'A key with an odd public key is negated and then tweaked',
    result: {
      output_key: 'ffd286d47c1895dccdec1243bdc12af662f50e1e51e6f0a6bdde919c4f98d734',
      private_key: '97312cc2a06c4c3b95b119fb9222d71d1399fd291e9b2b38c5eb41f1200f47ff',
    },
  },
  an_odd_key_is_negated_and_tweaked_with_a_merkle_root: {
    args: {
      merkle_root: '5b'.repeat(32),
      private_key: '68cfa8072f964148cb0dcedae42bbab417872739afef513314b29619ff3de9c4',
    },
    msg: 'A key with an odd public key is tweaked with a merkle root',
    result: {
      output_key: '33de5ddeccd49fea8821ad1ab53bb661c43bf3b448ea5036185d47e4267145cc',
      private_key: 'f9e738dc8ed303a093f16d0f14a0312e21e584562619e0398705efc38bdfd8c9',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, () => {
    const tweaked = taprootTweakedKey({
      merkle_root: args.merkle_root,
      private_key: hexAsBuffer(args.private_key),
    });

    strictSame(
      {
        output_key: tweaked.output_key,
        private_key: bufferAsHex(tweaked.private_key),
      },
      result,
      'Got expected tweaked key'
    );

    return;
  });
});
