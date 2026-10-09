const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {extendPsbt} = require('./../../');

const longHex = 'ab'.repeat(1e7);
const longPath = `m${'/0'.repeat(5e6)}`;
const template = '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000000';

// Test scenarios
const tests = {
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
  an_empty_final_scriptsig_is_kept: {
    args: {
      inputs: [{final_scriptsig: ''}],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000000',
    },
    msg: 'An empty final scriptSig is kept as a final scriptSig',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000107000000',
    },
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
        witness_script: '5121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae',
        witness_utxo: {
          script_pub: 'a9140591c3e786cce934d5294082533b3165cb9297c587',
          tokens: 100000,
        },
      }],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000000',
    },
    msg: 'A psbt is extended with input metadata',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000002206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f00000080000000000000000001070100010053010000000101010101010101010101010101010101010101010101010101010101010101010000000000ffffffff01a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c587000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c010104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa3010304010000000105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870000',
    },
  },
  a_taproot_input_is_extended_with_taproot_metadata: {
    args: {
      inputs: [{
        bip32_derivations: [
          {
            fingerprint: 'd90c6a4f',
            leaf_hashes: ['cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'],
            path: "m/0'/0/1",
            public_key: '9583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          },
        ],
        sighash_type: 1,
        taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01',
        witness_utxo: {
          script_pub: '51207777777777777777777777777777777777777777777777777777777777777777',
          tokens: 100000,
        },
      }],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000000',
    },
    msg: 'A taproot input is extended with taproot metadata',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa000000000021169583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f3101ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd90c6a4f00000080000000000100000001030401000000011341bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0101012ba08601000000000022512077777777777777777777777777777777777777777777777777777777777777770000',
    },
  },
  existing_records_are_kept: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
          sighash_type: 1,
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000002f0aa010100010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000000002f0bb010200',
    },
    msg: 'Existing signatures, key origins, and other records are kept',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000002f0aa010100010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c01010304010000000002f0bb010200',
    },
  },
  an_added_value_replaces_an_existing_value: {
    args: {
      inputs: [
        {
          sighash_type: 0x83,
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000000010304010000000000',
    },
    msg: 'An added value replaces the existing value with the same key',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000000010304830000000000',
    },
  },
  empty_redeem_and_witness_scripts_are_kept: {
    args: {
      inputs: [
        {
          redeem_script: '',
          witness_script: '',
        },
      ],
      psbt: template,
    },
    msg: 'Empty redeem and witness scripts are kept',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000104000105000000',
    },
  },
  a_taproot_key_origin_without_leaf_hashes_is_kept: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/86'/0'/0'/0/0",
              public_key: '9583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
        },
      ],
      psbt: template,
    },
    msg: 'A taproot key origin without leaf hashes is kept',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa000000000021169583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f1900d90c6a4f56000080000000800000008000000000000000000000',
    },
  },
  a_one_byte_taproot_signature_is_rejected: {
    args: {
      inputs: [
        {
          taproot_key_spend_sig: 'bb',
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedSizeOfTaprootKeySignature',
    msg: 'A one byte taproot key spend signature is rejected',
  },
  a_one_byte_taproot_signature_is_rejected_for_its_size: {
    args: {
      inputs: [
        {
          sighash_type: 1,
          taproot_key_spend_sig: 'bb',
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedSizeOfTaprootKeySignature',
    msg: 'A taproot signature of the wrong size is rejected for its size',
  },
  a_final_witness_with_the_wrong_element_count_is_rejected: {
    args: {
      inputs: [
        {
          final_scriptwitness: '0201aa',
        },
      ],
      psbt: template,
    },
    err: 'InvalidScriptWitness',
    msg: 'A final witness with the wrong element count is rejected',
  },
  a_script_with_non_hex_characters_is_rejected: {
    args: {
      inputs: [
        {
          redeem_script: '51zz',
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHexValueToExtendPsbt',
    msg: 'A script with characters that are not hex is rejected',
  },
  a_script_with_a_partial_byte_is_rejected: {
    args: {
      inputs: [
        {
          witness_script: '51f',
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHexValueToExtendPsbt',
    msg: 'A script with a partial byte is rejected',
  },
  a_very_long_field_that_is_not_hex_is_rejected: {
    args: {
      inputs: [
        {
          redeem_script: `${longHex}x`,
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHexValueToExtendPsbt',
    msg: 'A very long field that is not hex is rejected',
  },
  a_signature_with_extra_bytes_is_rejected: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c00',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedSignatureForPartialSignature',
    msg: 'A signature with extra bytes is rejected',
  },
  a_signature_that_is_not_hex_is_rejected: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: 'zz',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedSignatureForPartialSignature',
    msg: 'A signature that is not hex is rejected',
  },
  a_signature_public_key_must_be_hex: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: 'zz',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedPublicKeyForPartialSignature',
    msg: 'A signature public key that is not hex is rejected',
  },
  a_signature_flag_beyond_a_byte_is_rejected: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 257,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHashTypeByteForPartialSignature',
    msg: 'A signature hash type beyond one byte is rejected',
  },
  a_fractional_signature_flag_is_rejected: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1.5,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHashTypeByteForPartialSignature',
    msg: 'A fractional signature hash type is rejected',
  },
  a_fractional_sighash_is_rejected: {
    args: {
      inputs: [
        {
          sighash_type: 1.5,
        },
      ],
      psbt: template,
    },
    err: 'ExpectedUnsignedIntegerSigHashTypeToExtendPsbt',
    msg: 'A fractional sighash type is rejected',
  },
  a_sighash_beyond_32_bits_is_rejected: {
    args: {
      inputs: [
        {
          sighash_type: 2 ** 32,
        },
      ],
      psbt: template,
    },
    err: 'ExpectedUnsignedIntegerSigHashTypeToExtendPsbt',
    msg: 'A sighash type beyond 32 bits is rejected',
  },
  an_amount_that_is_not_a_number_is_rejected: {
    args: {
      inputs: [
        {
          witness_utxo: {
            script_pub: '51',
            tokens: true,
          },
        },
      ],
      psbt: template,
    },
    err: 'ExpectedNonNegativeTokensForWitnessUtxoToExtendPsbt',
    msg: 'A witness UTXO amount that is not a number is rejected',
  },
  a_witness_utxo_script_must_be_hex: {
    args: {
      inputs: [
        {
          witness_utxo: {
            script_pub: '5',
            tokens: 1,
          },
        },
      ],
      psbt: template,
    },
    err: 'ExpectedHexScriptPubForWitnessUtxoToExtendPsbt',
    msg: 'A witness UTXO script that is not hex is rejected',
  },
  metadata_for_a_missing_input_is_rejected: {
    args: {
      inputs: [
        {},
        {},
      ],
      psbt: template,
    },
    err: 'ExpectedMetadataForEachInputToExtendPsbt',
    msg: 'Metadata for an input the transaction does not have is rejected',
  },
  metadata_for_every_input_is_expected: {
    args: {
      inputs: [],
      psbt: template,
    },
    err: 'ExpectedMetadataForEachInputToExtendPsbt',
    msg: 'Metadata for every input of the transaction is expected',
  },
  metadata_must_be_an_object: {
    args: {
      inputs: [
        'abc',
      ],
      psbt: template,
    },
    err: 'ExpectedMetadataObjectForInputToExtendPsbt',
    msg: 'Input metadata that is not an object is rejected',
  },
  derivations_must_be_a_list: {
    args: {
      inputs: [
        {
          bip32_derivations: {
            fingerprint: 'd90c6a4f',
            path: "m/0'/0/0",
            public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          },
        },
      ],
      psbt: template,
    },
    err: 'ExpectedArrayOfBip32DerivationsToExtendPsbt',
    msg: 'Derivations that are not a list are rejected',
  },
  a_derivation_must_be_an_object: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            null,
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedBip32DerivationToExtendPsbt',
    msg: 'A derivation that is not an object is rejected',
  },
  a_derivation_fingerprint_must_be_four_bytes: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedFingerprintForBip32Derivation',
    msg: 'A derivation fingerprint that is not four bytes is rejected',
  },
  a_derivation_path_must_be_valid: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: 'm/1.5',
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedValidPathForBip32Derivation',
    msg: 'A derivation path with a fractional index is rejected',
  },
  a_very_long_derivation_path_that_is_not_valid_is_rejected: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: `${longPath}/x`,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedValidPathForBip32Derivation',
    msg: 'A very long derivation path that is not valid is rejected',
  },
  a_derivation_public_key_must_be_a_key: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f00',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedPublicKeyForBip32Derivation',
    msg: 'A derivation public key of the wrong length is rejected',
  },
  leaf_hashes_are_only_for_taproot_keys: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              leaf_hashes: [],
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedLeafHashesForTaprootBip32Derivation',
    msg: 'Leaf hashes for a public key that is not x-only are rejected',
  },
  leaf_hashes_must_be_hashes: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '9583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              leaf_hashes: [
                'cc',
              ],
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'ExpectedLeafHashesForTaprootBip32Derivation',
    msg: 'Leaf hashes that are not 32 byte hashes are rejected',
  },
  signatures_must_be_a_list: {
    args: {
      inputs: [
        {
          partial_sig: {
            hash_type: 1,
            public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
          },
        },
      ],
      psbt: template,
    },
    err: 'ExpectedArrayOfPartialSignaturesToExtendPsbt',
    msg: 'Signatures that are not a list are rejected',
  },
  a_final_witness_is_given_with_its_element_count: {
    args: {
      inputs: [
        {
          final_scriptwitness: '0201aa01bb',
        },
      ],
      psbt: template,
    },
    msg: 'A final witness is given as its element count and then its elements',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa00000000000108050201aa01bb0000',
    },
  },
  a_repeated_key_origin_is_rejected: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583BF39AE0A609747AD199ADDD634FA6108559D6C5CD39B4C2183F1AB96E07F',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedDuplicateBip32DerivationToExtendPsbt',
    msg: 'A key origin for a public key that already has one is rejected',
  },
  a_repeated_signature_is_rejected: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
            {
              hash_type: 1,
              public_key: '029583BF39AE0A609747AD199ADDD634FA6108559D6C5CD39B4C2183F1AB96E07F',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedDuplicatePartialSignatureToExtendPsbt',
    msg: 'A signature for a public key that already has one is rejected',
  },
  a_key_can_have_an_origin_and_a_signature_in_each_input: {
    args: {
      inputs: [
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
        {
          bip32_derivations: [
            {
              fingerprint: 'd90c6a4f',
              path: "m/0'/0/0",
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
          ],
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: '70736274ff0100680200000002a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffffa761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740100000000ffffffff010000000000000000036a01aa0000000000000000',
    },
    msg: 'A public key can have an origin and a signature in each input',
    result: {
      psbt: '70736274ff0100680200000002a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffffa761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740100000000ffffffff010000000000000000036a01aa00000000002206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c01002206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c010000',
    },
  },
  an_added_signature_must_use_the_added_sighash_type: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
          sighash_type: 2,
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'An added signature must use the sighash type added to its input',
  },
  an_added_signature_must_use_the_existing_sighash_type: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 2,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000000010304010000000000',
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'An added signature must use the existing sighash type of its input',
  },
  an_existing_signature_must_use_the_added_sighash_type: {
    args: {
      inputs: [
        {
          sighash_type: 2,
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000002f0aa010100010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c01010304010000000002f0bb010200',
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'An existing signature must use a sighash type added to its input',
  },
  a_signature_and_sighash_type_can_be_replaced_together: {
    args: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 2,
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
              signature: '6f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d21711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c',
            },
          ],
          sighash_type: 2,
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000002f0aa010100010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c01010304010000000002f0bb010200',
    },
    msg: 'A signature and the sighash type of its input are replaced together',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000002f0aa010100010120a08601000000000017a9140591c3e786cce934d5294082533b3165cb9297c5870104220020e0ba5e24cac5375c5cdf78c6c3f39721f36f3ac64d480314c573285cc8baffa30105255121029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f51ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f0000008000000000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f47304402206f14e6a6f550303f483cc6afa8eb1b3a3403ae776704787edb37290e9f120b6d022021711c508e8bb80135460407949b01b2194ef57a3fe2ae4c15207d8db085e60c02010304020000000002f0bb010200',
    },
  },
  a_short_taproot_signature_uses_the_default_sighash_type: {
    args: {
      inputs: [
        {
          sighash_type: 0,
          taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
      psbt: template,
    },
    msg: 'A 64 byte taproot signature uses the default sighash type',
    result: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa000000000001030400000000011340bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000',
    },
  },
  a_short_taproot_signature_must_use_the_sighash_type: {
    args: {
      inputs: [
        {
          sighash_type: 1,
          taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'A 64 byte taproot signature must be for a default sighash input',
  },
  a_taproot_signature_must_use_the_sighash_type: {
    args: {
      inputs: [
        {
          sighash_type: 1,
          taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb02',
        },
      ],
      psbt: template,
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'A taproot signature must use the sighash type of its input',
  },
  a_taproot_signature_must_use_the_existing_sighash_type: {
    args: {
      inputs: [
        {
          taproot_key_spend_sig: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        },
      ],
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa0000000000010304010000000000',
    },
    err: 'UnexpectedSigHashTypeForInputSignature',
    msg: 'A taproot signature must use the existing sighash type of its input',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, () => {
    if (!!err) {
      throws(() => extendPsbt(args), new Error(err));

      return;
    }

    equal(extendPsbt(args).psbt, result.psbt);

    return;
  });
});
