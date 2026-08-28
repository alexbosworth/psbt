const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const tinysecp = require('tiny-secp256k1');

const {extendPsbt} = require('./../../');

// Test scenarios
const tests = {
  an_ecpair_object_is_expected: {
    args: {ecp: undefined, inputs: [], psbt: '00'},
    err: 'ExpectedEcpairObjectToExtendPsbt',
    msg: 'An ecpair object is expected',
  },
  an_array_of_inputs_is_expected: {
    args: {psbt: '00'},
    err: 'ExpectedArrayOfInputMetadataToExtendPsbt',
    msg: 'An array of input metadata is expected',
  },
  a_psbt_to_extend_is_expected: {
    args: {inputs: []},
    err: 'ExpectedPsbtToExtend',
    msg: 'A psbt to extend is expected',
  },
  a_psbt_is_extended_with_input_metadata: {
    args: {
      inputs: [{
        bip32_derivations: [
          {
            fingerprint: 'd90c6a4f',
            path: "m/0'/0/0",
            public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          },
          {
            fingerprint: 'd90c6a4f',
            leaf_hashes: ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'],
            path: "m/0'/0/1",
            public_key: '9583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          },
        ],
        final_scriptsig: '00',
        non_witness_utxo: '010000000101010101010101010101010101010101010101010101010101010101010101010000000000ffffffff01a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c58700000000',
        partial_sig: [{
          hash_type: 1,
          public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
        }],
        redeem_script: '0020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa3',
        sighash_type: 1,
        taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        witness_script: '5121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae',
        witness_utxo: {
          script_pub: '0020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa3',
          tokens: 100000,
        },
      }],
      psbt: '70736274ff01003f0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff010000000000000000036a01aa00000000000000',
    },
    msg: 'A psbt is extended with input metadata',
    result: {
      psbt: '70736274ff01003f0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff010000000000000000036a01aa00000000002206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f00000080000000000000000021169583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f3101ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd90c6a4f00000080000000000100000001070100010053010000000101010101010101010101010101010101010101010101010101010101010101010000000000ffffffff01a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c587000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c010104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa301030401000000011340bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae01012ba086010000000000220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30000',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, async () => {
    const ecp = (await import('ecpair')).ECPairFactory(tinysecp);

    if (!('ecp' in args)) {
      args.ecp = ecp;
    }

    if (!!err) {
      throws(() => extendPsbt(args), new Error(err));

      return;
    }

    equal(extendPsbt(args).psbt, result.psbt);

    return;
  });
});
