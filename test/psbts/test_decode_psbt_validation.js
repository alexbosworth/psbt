const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodePsbt} = require('./../../');

// Test scenarios
const tests = {
  a_version_before_the_unsigned_transaction_is_accepted: {
    args: {
      psbt: '70736274ff01fb04000000000100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000000',
    },
    msg: 'Global keys may come before the unsigned transaction',
    result: {
      inputs: [{}],
      outputs: [{}],
      pairs: [
        {
          type: 'fb',
          value: '00000000',
        },
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
      ],
      unrecognized_attributes: [
        {
          type: 'fb',
          value: '00000000',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_global_section_without_a_transaction_is_rejected: {
    args: {
      psbt: '70736274ff01fb0400000000000000',
    },
    err: 'ExpectedUnsignedTransaction',
    msg: 'The whole global section is read before requiring a transaction',
  },
  an_unsupported_version_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000001fb0402000000000000',
    },
    err: 'UnsupportedPsbtVersion',
    msg: 'A PSBT version other than 0 is rejected',
  },
  an_incorrectly_sized_version_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000001fb03000000000000',
    },
    err: 'UnexpectedPsbtVersionByteLength',
    msg: 'A version that is not 4 bytes is rejected',
  },
  a_version_key_with_key_data_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000002fb000400000000000000',
    },
    err: 'InvalidPsbtVersionTypeKey',
    msg: 'A version key with key data is rejected',
  },
  a_key_value_after_the_final_section_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000000001fc0100',
    },
    err: 'UnexpectedDataAfterFinalPsbtSection',
    msg: 'A key value pair after the final section is rejected',
  },
  a_separator_after_the_final_section_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000000000',
    },
    err: 'UnexpectedDataAfterFinalPsbtSection',
    msg: 'An extra separator after the final section is rejected',
  },
  a_value_missing_promised_bytes_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000008fc0570736274780004aa',
    },
    err: 'ExpectedMoreBytesForPsbtKeyOrValue',
    msg: 'A value with fewer bytes than its length promises is rejected',
  },
  a_key_missing_promised_bytes_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000005fc05',
    },
    err: 'ExpectedMoreBytesForPsbtKeyOrValue',
    msg: 'A key with fewer bytes than its length promises is rejected',
  },
  a_key_type_missing_bytes_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000002fd01010000',
    },
    err: 'InvalidPsbtKeyTypeEncoding',
    msg: 'A multi-byte key type with missing bytes is rejected',
  },
  a_non_minimal_key_type_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000003fd0100010000',
    },
    err: 'InvalidPsbtKeyTypeEncoding',
    msg: 'A key type that is not minimally encoded is rejected',
  },
  a_minimal_multi_byte_key_type_is_kept_as_unrecognized: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000004fdfd00aa010100',
    },
    msg: 'A valid multi-byte key type is kept as an unrecognized attribute',
    result: {
      inputs: [{}],
      outputs: [
        {
          unrecognized_attributes: [
            {
              type: 'fdfd00aa',
              value: '01',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: 'fdfd00aa',
          value: '01',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_witness_utxo_before_a_non_witness_utxo_is_accepted: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000001011f50c30000000000001600143333333333333333333333333333333333333333010072020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f87000000000000',
    },
    msg: 'Both UTXO forms are accepted with the witness UTXO first',
    result: {
      inputs: [
        {
          witness_utxo: {
            tokens: 50000,
            script_pub: '00143333333333333333333333333333333333333333',
          },
          non_witness_utxo: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '01',
          value: '50c30000000000001600143333333333333333333333333333333333333333',
        },
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_non_witness_utxo_before_a_witness_utxo_is_accepted: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010072020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f870000000001011f50c300000000000016001433333333333333333333333333333333333333330000',
    },
    msg: 'Both UTXO forms are accepted with the non-witness UTXO first',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
          witness_utxo: {
            tokens: 50000,
            script_pub: '00143333333333333333333333333333333333333333',
          },
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
        },
        {
          type: '01',
          value: '50c30000000000001600143333333333333333333333333333333333333333',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_redeem_script_matching_the_spent_output_is_accepted: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80100000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010072020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000010416001444444444444444444444444444444444444444440000',
    },
    msg: 'A redeem script matching the spent output is accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
          redeem_script: '00144444444444444444444444444444444444444444',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80100000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000',
        },
        {
          type: '04',
          value: '00144444444444444444444444444444444444444444',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80100000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_redeem_script_matching_only_another_output_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010072020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000010416001444444444444444444444444444444444444444440000',
    },
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'A redeem script matching only an unspent output is rejected',
  },
  a_missing_spent_output_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80500000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010072020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0250c3000000000000160014333333333333333333333333333333333333333360ea00000000000017a91458753dfe4be2a8373e77ce6a77f1feb1050f847f8700000000010416001444444444444444444444444444444444444444440000',
    },
    err: 'ExpectedSpentOutputInNonWitnessUtxo',
    msg: 'A non-witness UTXO without the spent output is rejected',
  },
  a_final_witness_is_read_by_element_lengths: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000108fd57010251111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111fd010122222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222220000',
    },
    msg: 'A final witness is read by its element lengths and kept exactly',
    result: {
      inputs: [
        {
          final_scriptwitness: '51111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111fd01012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '08',
          value: '0251111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111fd01012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_final_witness_with_too_few_elements_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000001080503015101aa0000',
    },
    err: 'InvalidScriptWitness',
    msg: 'A final witness with fewer elements than its count is rejected',
  },
  a_final_witness_with_a_truncated_element_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000108040105aabb0000',
    },
    err: 'InvalidScriptWitness',
    msg: 'A final witness element missing bytes is rejected',
  },
  a_tap_key_sig_key_with_key_data_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000002130040abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab0000',
    },
    err: 'InvalidTapKeySigTypeKey',
    msg: 'A tap key sig key with key data is rejected',
  },
  a_tap_internal_key_key_with_key_data_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000217002050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000',
    },
    err: 'InvalidTapInternalKeyTypeKey',
    msg: 'A tap internal key key with key data is rejected',
  },
  a_tap_merkle_root_key_with_key_data_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000002180020eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000',
    },
    err: 'InvalidTapMerkleRootTypeKey',
    msg: 'A tap merkle root key with key data is rejected',
  },
  a_tap_tree_key_with_key_data_is_rejected: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000022512077777777777777777777777777777777777777777777777777777777777777770000000000000206000401c0015100',
    },
    err: 'InvalidOutputTapTreeTypeKey',
    msg: 'A tap tree key with key data is rejected',
  },
  a_witness_utxo_with_extra_script_bytes_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000001011f50c300000000000001001433333333333333333333333333333333333333330000',
    },
    err: 'UnexpectedScriptPubLengthForWitnessUtxo',
    msg: 'A witness UTXO script longer than its stated length is rejected',
  },
  a_witness_utxo_with_missing_script_bytes_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000001011e50c3000000000000161433333333333333333333333333333333333333330000',
    },
    err: 'UnexpectedScriptPubLengthForWitnessUtxo',
    msg: 'A witness UTXO script shorter than its stated length is rejected',
  },
  a_leaf_hash_count_beyond_the_value_is_rejected: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000002251207777777777777777777777777777777777777777777777777777777777777777000000000000210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac009fe40420f00d90c6a4f00',
    },
    err: 'UnexpectedLeafHashesCountForTaprootDerivation',
    msg: 'A leaf hash count beyond the bytes present is rejected',
  },
  a_tap_derivation_without_a_fingerprint_is_rejected: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000002251207777777777777777777777777777777777777777777777777777777777777777000000000000210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00300aabb00',
    },
    err: 'ExpectedFingerprintInBip32Derivation',
    msg: 'A tap derivation without a key fingerprint is rejected',
  },
  a_tap_derivation_with_a_partial_path_is_rejected: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000002251207777777777777777777777777777777777777777777777777777777777777777000000000000210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00700d90c6a4f560000',
    },
    err: 'ExpectedCompletePathElementsInBip32Derivation',
    msg: 'A tap derivation with a partial path element is rejected',
  },
  a_derivation_without_a_fingerprint_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f02aabb00',
    },
    err: 'ExpectedFingerprintInBip32Derivation',
    msg: 'A derivation without a key fingerprint is rejected',
  },
  a_tap_tree_leaf_missing_script_bytes_is_rejected: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060401c003aa00',
    },
    err: 'ExpectedFullScriptForTaprootTreeLeaf',
    msg: 'A tap tree leaf with fewer script bytes than promised is rejected',
  },
  every_output_derivation_is_kept: {
    args: {
      psbt: '70736274ff01005e0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000022512077777777777777777777777777777777777777777777777777777777777777770000000000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f56000080000000800000008022020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179810d90c6a4f560000800000008000000080210750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac03101c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1d90c6a4f56000080000000800000008000',
    },
    msg: 'Every output derivation is kept in a collection',
    result: {
      inputs: [{}],
      outputs: [
        {
          bip32_derivation: {
            fingerprint: 'd90c6a4f',
            leaf_hashes: [
              'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
            ],
            path: `m/86'/0'/0'`,
            public_key: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
          },
          bip32_derivations: [
            {
              path: `m/86'/0'/0'`,
              fingerprint: 'd90c6a4f',
              public_key: '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
            },
            {
              path: `m/86'/0'/0'`,
              fingerprint: 'd90c6a4f',
              public_key: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            },
            {
              fingerprint: 'd90c6a4f',
              leaf_hashes: [
                'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
              ],
              path: `m/86'/0'/0'`,
              public_key: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
        },
        {
          type: '02029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
          value: 'd90c6a4f560000800000008000000080',
        },
        {
          type: '020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          value: 'd90c6a4f560000800000008000000080',
        },
        {
          type: '0750929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
          value: '01c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1d90c6a4f560000800000008000000080',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
    },
  },
  every_tap_script_signature_is_kept: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000411450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c140abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab411450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c241abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab830000',
    },
    msg: 'Every tap script signature is kept with its own sighash type',
    result: {
      inputs: [
        {
          taproot_leaf_hash: 'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
          taproot_leaf_public_key: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
          taproot_script_signature: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
          taproot_script_signatures: [
            {
              hash_type: 0,
              leaf_hash: 'c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
              public_key: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
              signature: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
            },
            {
              hash_type: 131,
              leaf_hash: 'c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
              public_key: '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
              signature: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
            },
          ],
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '1450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1',
          value: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
        },
        {
          type: '1450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2',
          value: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab83',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_sighash_type_before_a_tap_key_sig_is_kept: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000001030401000000011341abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab830000',
    },
    msg: 'The input sighash type is kept apart from a later signature sighash',
    result: {
      inputs: [
        {
          sighash_type: 1,
          taproot_key_spend_sig: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
          taproot_key_spend_sig_hash_type: 131,
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '03',
          value: '01000000',
        },
        {
          type: '13',
          value: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab83',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_sighash_type_after_a_tap_key_sig_is_kept: {
    args: {
      psbt: '70736274ff0100520200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000011341abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab83010304010000000000',
    },
    msg: 'The input sighash type is kept apart from a signature sighash',
    result: {
      inputs: [
        {
          taproot_key_spend_sig: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
          taproot_key_spend_sig_hash_type: 131,
          sighash_type: 1,
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '13',
          value: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab83',
        },
        {
          type: '03',
          value: '01000000',
        },
      ],
      unsigned_transaction: '0200000001e1566307bde0cab07ccaba4fc101a34a102c436dcdcbc6a3d2e8da58fe8488e80000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_psbt_with_a_non_hex_character_is_rejected: {
    args: {
      psbt: '70736274ff01003d0200zz000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000000000',
    },
    err: 'ExpectedHexSerializedPartiallySignedBitcoinTransaction',
    msg: 'A PSBT with a non-hex character is rejected',
  },
  a_psbt_with_a_trailing_odd_digit_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a000000000000000',
    },
    err: 'ExpectedHexSerializedPartiallySignedBitcoinTransaction',
    msg: 'A PSBT with a leftover single hex digit is rejected',
  },
  a_psbt_that_is_not_text_is_rejected: {
    args: {
      psbt: 7,
    },
    err: 'ExpectedHexSerializedPartiallySignedBitcoinTransaction',
    msg: 'A PSBT that is not a string is rejected',
  },
  an_uppercase_hex_psbt_is_decoded: {
    args: {
      psbt: '70736274FF01003D020000000111111111111111111111111111111111111111111111111111111111111111110000000000FFFFFFFF01E803000000000000016A00000000000000',
    },
    msg: 'An uppercase hex PSBT is decoded',
    result: {
      inputs: [{}],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000',
    },
  },
  a_key_sig_with_a_zero_sighash_byte_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a0000000000011341abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab000000',
    },
    err: 'UnexpectedSigHashTypeForTaprootKeySignature',
    msg: 'A 65 byte key spend signature with a zero sighash byte is rejected',
  },
  a_key_sig_with_an_unknown_sighash_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a0000000000011341abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab840000',
    },
    err: 'UnexpectedSigHashTypeForTaprootKeySignature',
    msg: 'A key spend signature with an unknown sighash type is rejected',
  },
  a_script_sig_with_an_unknown_sighash_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a0000000000411450929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c141abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab040000',
    },
    err: 'UnexpectedSigHashTypeForTaprootScriptSignature',
    msg: 'A script spend signature with an unknown sighash type is rejected',
  },
  a_key_sig_with_an_allowed_sighash_is_decoded: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a0000000000011341abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab820000',
    },
    msg: 'A key spend signature with an allowed sighash type is decoded',
    result: {
      inputs: [
        {
          taproot_key_spend_sig: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab',
          taproot_key_spend_sig_hash_type: 130,
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000',
        },
        {
          type: '13',
          value: 'abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab82',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000',
    },
  },
  a_leaf_script_version_must_match_its_control_block: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000002215c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00251c20000',
    },
    err: 'UnexpectedControlBlockLeafVersionForLeafScript',
    msg: 'A leaf script version unlike its control block is rejected',
  },
  an_odd_leaf_script_version_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a00000000002215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00251c10000',
    },
    err: 'InvalidLeafVersionForTapLeafScriptInput',
    msg: 'An odd leaf script version is rejected',
  },
  an_annex_tag_leaf_script_version_is_rejected: {
    args: {
      psbt: '70736274ff01003d020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000016a000000000022155050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00251500000',
    },
    err: 'InvalidLeafVersionForTapLeafScriptInput',
    msg: 'A leaf script version equal to the annex tag is rejected',
  },
  an_empty_tap_tree_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060000',
    },
    err: 'ExpectedCompleteTaprootTree',
    msg: 'An empty tap tree is rejected',
  },
  a_tap_tree_with_a_missing_branch_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060401c0015100',
    },
    err: 'ExpectedCompleteTaprootTree',
    msg: 'A tap tree with a missing branch is rejected',
  },
  a_tap_tree_with_two_roots_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060800c0015100c0015100',
    },
    err: 'ExpectedCompleteTaprootTree',
    msg: 'A tap tree with two roots is rejected',
  },
  a_tap_tree_out_of_depth_first_order_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001061001c0015102c0015101c0015102c0015100',
    },
    err: 'ExpectedCompleteTaprootTree',
    msg: 'A tap tree whose leaves are not in depth first order is rejected',
  },
  a_tap_tree_that_is_too_deep_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060481c0015100',
    },
    err: 'UnexpectedDepthForTaprootTreeLeaf',
    msg: 'A tap tree deeper than 128 levels is rejected',
  },
  a_tap_tree_with_an_odd_leaf_version_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060801c1015101c0015100',
    },
    err: 'InvalidLeafVersionForTaprootTreeLeaf',
    msg: 'A tap tree leaf with an odd leaf version is rejected',
  },
  a_tap_tree_with_an_annex_tag_version_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060801c001510150015100',
    },
    err: 'InvalidLeafVersionForTaprootTreeLeaf',
    msg: 'A tap tree leaf with the annex tag as its version is rejected',
  },
  a_single_leaf_tap_tree_is_decoded: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060400c0015100',
    },
    msg: 'A tap tree that is a single leaf is decoded',
    result: {
      inputs: [{}],
      outputs: [
        {
          taproot_script_tree: [
            {
              depth: 0,
              version: 192,
              script: '51',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
        },
        {
          type: '06',
          value: '00c00151',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
    },
  },
  an_uneven_complete_tap_tree_is_decoded: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000000001060c02c0015102c0015201c0015300',
    },
    msg: 'A complete tap tree with leaves at different depths is decoded',
    result: {
      inputs: [{}],
      outputs: [
        {
          taproot_script_tree: [
            {
              depth: 2,
              version: 192,
              script: '51',
            },
            {
              depth: 2,
              version: 192,
              script: '52',
            },
            {
              depth: 1,
              version: 192,
              script: '53',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
        },
        {
          type: '06',
          value: '02c0015102c0015201c00153',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000225120777777777777777777777777777777777777777777777777777777777777777700000000',
    },
  },
  a_psbt_with_two_empty_inputs_and_outputs: {
    args: {
      psbt: '70736274ff010070020000000211111111111111111111111111111111111111111111111111111111111111110000000000ffffffff22222222222222222222222222222222222222222222222222222222222222220100000000ffffffff02e803000000000000016ae803000000000000016a000000000000000000',
    },
    msg: 'A PSBT with two empty inputs and outputs is decoded',
    result: {
      inputs: [{}, {}],
      outputs: [{}, {}],
      pairs: [
        {
          type: '00',
          value: '020000000211111111111111111111111111111111111111111111111111111111111111110000000000ffffffff22222222222222222222222222222222222222222222222222222222222222220100000000ffffffff02e803000000000000016ae803000000000000016a00000000',
        },
      ],
      unsigned_transaction: '020000000211111111111111111111111111111111111111111111111111111111111111110000000000ffffffff22222222222222222222222222222222222222222222222222222222222222220100000000ffffffff02e803000000000000016ae803000000000000016a00000000',
    },
  },
  an_uncompressed_public_key_is_kept_as_it_was_given: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000042020479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c0142060479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b810d90c6a4f0000008000000080000000800042020479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b810d90c6a4f00000080000000800000008000',
    },
    msg: 'Uncompressed public keys are not changed to compressed keys',
    result: {
      inputs: [
        {
          partial_sig: [
            {
              hash_type: 1,
              public_key: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
              signature: '74018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c9973d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c',
            },
          ],
          bip32_derivations: [
            {
              path: `m/0'/0'/0'`,
              fingerprint: 'd90c6a4f',
              public_key: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            },
          ],
        },
      ],
      outputs: [
        {
          bip32_derivation: {
            path: `m/0'/0'/0'`,
            fingerprint: 'd90c6a4f',
            public_key: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
          },
          bip32_derivations: [
            {
              path: `m/0'/0'/0'`,
              fingerprint: 'd90c6a4f',
              public_key: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '020479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
          value: '3044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01',
        },
        {
          type: '060479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
          value: 'd90c6a4f000000800000008000000080',
        },
        {
          type: '020479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
          value: 'd90c6a4f000000800000008000000080',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_partial_signature_with_an_oversized_number_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000022020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483045022101111111111111111111111111111111111111111111111111111111111111111102202222222222222222222222222222222222222222222222222222222222222222010000',
    },
    err: 'ExpectedValidPartialSignature',
    msg: 'A signature number that does not fit is rejected',
  },
  a_version_2_global_field_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000001020402000000000000',
    },
    err: 'UnexpectedPsbtVersion2GlobalField',
    msg: 'A global field reserved for version 2 is rejected',
  },
  a_version_2_silent_payment_global_field_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000022070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798000000',
    },
    err: 'UnexpectedPsbtVersion2GlobalField',
    msg: 'A global silent payment field reserved for version 2 is rejected',
  },
  a_version_2_input_field_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010e2011111111111111111111111111111111111111111111111111111111111111110000',
    },
    err: 'UnexpectedPsbtVersion2InputField',
    msg: 'An input field reserved for version 2 is rejected',
  },
  a_version_2_output_field_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000000104160014555555555555555555555555555555555555555500',
    },
    err: 'UnexpectedPsbtVersion2OutputField',
    msg: 'An output field reserved for version 2 is rejected',
  },
  a_global_xpub_with_a_matching_key_origin_is_accepted: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179808d90c6a4f000000804f010488b21e000000000000000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179804d90c6a4f000000',
    },
    msg: 'A global xpub with a path for each depth is accepted',
    result: {
      inputs: [{}],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          value: 'd90c6a4f00000080',
        },
        {
          type: '010488b21e000000000000000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          value: 'd90c6a4f',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
      unrecognized_attributes: [
        {
          type: '010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          value: 'd90c6a4f00000080',
        },
        {
          type: '010488b21e000000000000000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          value: 'd90c6a4f',
        },
      ],
    },
  },
  a_global_xpub_with_a_short_key_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004e010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81708d90c6a4f00000080000000',
    },
    err: 'ExpectedSerializedExtendedPublicKeyForGlobalXpub',
    msg: 'A global xpub key must be a complete extended public key',
  },
  a_global_xpub_with_an_invalid_public_key_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff08d90c6a4f00000080000000',
    },
    err: 'InvalidPublicKeyForGlobalXpub',
    msg: 'A global xpub must have a valid public key',
  },
  a_global_master_xpub_with_a_parent_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e00d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179804d90c6a4f000000',
    },
    err: 'UnexpectedParentForMasterGlobalXpub',
    msg: 'A depth zero global xpub cannot have a parent',
  },
  a_global_xpub_without_a_fingerprint_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802d90c000000',
    },
    err: 'ExpectedFingerprintInBip32Derivation',
    msg: 'A global xpub key origin must have a fingerprint',
  },
  a_global_xpub_with_a_partial_path_element_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179807d90c6a4f000000000000',
    },
    err: 'ExpectedCompletePathElementsInBip32Derivation',
    msg: 'A global xpub key origin must have whole path elements',
  },
  a_global_xpub_with_a_path_longer_than_its_depth_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000004f010488b21e01d90c6a4f80000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980cd90c6a4f0000008000000080000000',
    },
    err: 'UnexpectedPathLengthForGlobalXpubDepth',
    msg: 'A global xpub path must match its depth',
  },
  proprietary_keys_with_identifiers_and_subtypes_are_accepted: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000008fc0570736274780003c0ffee0dfc00ff0000000000000080abcd00000cfc057073627478fd0001beef01010008fc05707362747801010200',
    },
    msg: 'Proprietary keys with an identifier and subtype are kept',
    result: {
      inputs: [
        {
          unrecognized_attributes: [
            {
              type: 'fc057073627478fd0001beef',
              value: '01',
            },
          ],
        },
      ],
      outputs: [
        {
          unrecognized_attributes: [
            {
              type: 'fc05707362747801',
              value: '02',
            },
          ],
        },
      ],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: 'fc05707362747800',
          value: 'c0ffee',
        },
        {
          type: 'fc00ff0000000000000080abcd',
          value: '',
        },
        {
          type: 'fc057073627478fd0001beef',
          value: '01',
        },
        {
          type: 'fc05707362747801',
          value: '02',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
      unrecognized_attributes: [
        {
          type: 'fc05707362747800',
          value: 'c0ffee',
        },
        {
          type: 'fc00ff0000000000000080abcd',
          value: '',
        },
      ],
    },
  },
  a_proprietary_key_without_an_identifier_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000001fc0100000000',
    },
    err: 'ExpectedIdentifierInProprietaryKey',
    msg: 'A proprietary key must have an identifier',
  },
  a_proprietary_key_with_a_cut_off_identifier_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000004fc05707301000000',
    },
    err: 'ExpectedIdentifierInProprietaryKey',
    msg: 'A proprietary key identifier must be complete',
  },
  a_proprietary_key_without_a_subtype_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000007fc057073627478010000',
    },
    err: 'ExpectedSubtypeInProprietaryKey',
    msg: 'A proprietary key must have a subtype',
  },
  a_proprietary_key_with_a_non_minimal_subtype_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000afc057073627478fd010001000000',
    },
    err: 'ExpectedSubtypeInProprietaryKey',
    msg: 'A proprietary key subtype must be minimally encoded',
  },
  hash_preimages_that_match_their_hashes_are_accepted: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000150a5f0db60133b07c60425104ce7c62f3d797af667a08707265696d616765210b107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f08707265696d616765150c5d134d6fcd67e60ff01353700cd6aaa2bf568c7008707265696d616765210d6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533308707265696d6167650000',
    },
    msg: 'Hash preimages that hash to their keys are kept',
    result: {
      inputs: [
        {
          unrecognized_attributes: [
            {
              type: '0a5f0db60133b07c60425104ce7c62f3d797af667a',
              value: '707265696d616765',
            },
            {
              type: '0b107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f',
              value: '707265696d616765',
            },
            {
              type: '0c5d134d6fcd67e60ff01353700cd6aaa2bf568c70',
              value: '707265696d616765',
            },
            {
              type: '0d6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333',
              value: '707265696d616765',
            },
          ],
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '0a5f0db60133b07c60425104ce7c62f3d797af667a',
          value: '707265696d616765',
        },
        {
          type: '0b107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f',
          value: '707265696d616765',
        },
        {
          type: '0c5d134d6fcd67e60ff01353700cd6aaa2bf568c70',
          value: '707265696d616765',
        },
        {
          type: '0d6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333',
          value: '707265696d616765',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_preimage_without_a_hash_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000010b08707265696d6167650000',
    },
    err: 'UnexpectedHashLengthForPreimage',
    msg: 'A hash preimage key must contain the hash',
  },
  a_preimage_with_the_wrong_hash_length_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000150b5f0db60133b07c60425104ce7c62f3d797af667a08707265696d6167650000',
    },
    err: 'UnexpectedHashLengthForPreimage',
    msg: 'A hash preimage key must have the hash length of its type',
  },
  a_preimage_that_does_not_match_its_hash_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c00000000000016001455555555555555555555555555555555555555550000000000210d107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f08707265696d6167650000',
    },
    err: 'ExpectedPreimageMatchingHash',
    msg: 'A hash preimage must hash to its key',
  },
  a_very_large_unknown_key_type_is_accepted: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000000affffffffffffffff7faa01bb0000',
    },
    msg: 'Unknown key types beyond the safe number limit are kept',
    result: {
      inputs: [
        {
          unrecognized_attributes: [
            {
              type: 'ffffffffffffffff7faa',
              value: 'bb',
            },
          ],
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: 'ffffffffffffffff7faa',
          value: 'bb',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_non_minimal_very_large_key_type_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01409c0000000000001600145555555555555555555555555555555555555555000000000009ff010000000000000001bb0000',
    },
    err: 'InvalidPsbtKeyTypeEncoding',
    msg: 'Key types must be minimally encoded at any size',
  },
  a_transaction_without_inputs_is_read_in_the_legacy_format: {
    args: {
      psbt: '70736274ff01002902000000000170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d000000000000',
    },
    msg: 'An unsigned transaction without inputs is not read as SegWit',
    result: {
      inputs: [],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '02000000000170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00000000',
        },
      ],
      unsigned_transaction: '02000000000170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00000000',
    },
  },
  a_native_witness_script_that_matches_its_output_is_accepted: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001012b50c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260010501510000',
    },
    msg: 'A witness script hashing to its native output is accepted',
    result: {
      inputs: [
        {
          witness_utxo: {
            tokens: 50000,
            script_pub: '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
          },
          witness_script: '51',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '01',
          value: '50c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
        },
        {
          type: '05',
          value: '51',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_native_witness_script_that_does_not_match_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001012b50c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260010501520000',
    },
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script not hashing to its native output is rejected',
  },
  an_ordinary_redeem_script_for_a_nested_witness_output_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001012050c300000000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87010401510000',
    },
    err: 'ExpectedWitnessProgramForNestedRedeemScript',
    msg: 'A nested output with a non-witness-program redeem is rejected',
  },
  an_empty_redeem_script_for_a_nested_witness_output_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001012050c300000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb870104000000',
    },
    err: 'ExpectedWitnessVersion',
    msg: 'An empty redeem script for a nested witness output is rejected',
  },
  an_empty_redeem_script_that_matches_is_accepted: {
    args: {
      psbt: '70736274ff0100520200000001655b92a9244539b0a7b39d982d8e4c5be8a6534c3d11a885775d9bef8d9cca1b0000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010053020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87000000000104000000',
    },
    msg: 'An empty redeem script that the spent output pays to is accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb8700000000',
          redeem_script: '',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001655b92a9244539b0a7b39d982d8e4c5be8a6534c3d11a885775d9bef8d9cca1b0000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb8700000000',
        },
        {
          type: '04',
          value: '',
        },
      ],
      unsigned_transaction: '0200000001655b92a9244539b0a7b39d982d8e4c5be8a6534c3d11a885775d9bef8d9cca1b0000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  an_empty_redeem_script_that_does_not_match_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001f909e7c7d0a55721976d0246da3d1dd0fac9082af34752cf71a1076299c3645e0000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010053020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87000000000104000000',
    },
    err: 'RedeemScriptDoesNotMatchUtxo',
    msg: 'An empty redeem script the spent output does not pay is rejected',
  },
  a_witness_script_matching_a_spent_witness_output_is_accepted: {
    args: {
      psbt: '70736274ff010052020000000172d1d92f961d9277c8f2615dd25f65f5d4730357b8b2a6e92aaa700b3cb516c90000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001005e020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000010501510000',
    },
    msg: 'A witness script hashing to a full UTXO witness output is accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000',
          witness_script: '51',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '020000000172d1d92f961d9277c8f2615dd25f65f5d4730357b8b2a6e92aaa700b3cb516c90000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000',
        },
        {
          type: '05',
          value: '51',
        },
      ],
      unsigned_transaction: '020000000172d1d92f961d9277c8f2615dd25f65f5d4730357b8b2a6e92aaa700b3cb516c90000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_witness_script_not_matching_a_spent_witness_output_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000172d1d92f961d9277c8f2615dd25f65f5d4730357b8b2a6e92aaa700b3cb516c90000000000ffffffff0150c30000000000001600145555555555555555555555555555555555555555000000000001005e020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326000000000010501520000',
    },
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script unlike a full UTXO witness output is rejected',
  },
  a_nested_witness_script_matching_its_redeem_script_is_accepted: {
    args: {
      psbt: '70736274ff01005202000000019b9b8b1e9aca71aef1a5c186388edf928e13dd33faacfea7f6e51b41f29c226b0000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010053020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870000000001042200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260010501510000',
    },
    msg: 'A witness script hashing to a full UTXO redeem program is accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a91472c44f957fc011d97e3406667dca5b1c930c40268700000000',
          redeem_script: '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
          witness_script: '51',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '02000000019b9b8b1e9aca71aef1a5c186388edf928e13dd33faacfea7f6e51b41f29c226b0000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a91472c44f957fc011d97e3406667dca5b1c930c40268700000000',
        },
        {
          type: '04',
          value: '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
        },
        {
          type: '05',
          value: '51',
        },
      ],
      unsigned_transaction: '02000000019b9b8b1e9aca71aef1a5c186388edf928e13dd33faacfea7f6e51b41f29c226b0000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_nested_witness_script_not_matching_its_redeem_script_is_rejected: {
    args: {
      psbt: '70736274ff01005202000000019b9b8b1e9aca71aef1a5c186388edf928e13dd33faacfea7f6e51b41f29c226b0000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010053020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c300000000000017a91472c44f957fc011d97e3406667dca5b1c930c4026870000000001042200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260010501520000',
    },
    err: 'InvalidRedeemScriptHashForWitnessScript',
    msg: 'A witness script unlike a full UTXO redeem program is rejected',
  },
  a_witness_script_for_a_spent_output_without_a_program_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001775bec09ff040a5dad414d3f83d5bfecce042341c3ff282e72e6bd9ac1b9b83e0000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010055020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000001976a914111111111111111111111111111111111111111188ac00000000010501510000',
    },
    err: 'WitnessScriptDoesNotMatchUtxo',
    msg: 'A witness script for a full UTXO without a program is rejected',
  },
  a_previous_transaction_that_the_input_spends_is_accepted: {
    args: {
      psbt: '70736274ff0100520200000001284962f42317232fbf9499086ea66d4a21ae12c1ad1dafd09e7db382164466870000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010052020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c30000000000001600143333333333333333333333333333333333333333000000000000',
    },
    msg: 'A full previous transaction with the spent id is accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c3000000000000160014333333333333333333333333333333333333333300000000',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '0200000001284962f42317232fbf9499086ea66d4a21ae12c1ad1dafd09e7db382164466870000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '020000000199999999999999999999999999999999999999999999999999999999999999990000000000ffffffff0150c3000000000000160014333333333333333333333333333333333333333300000000',
        },
      ],
      unsigned_transaction: '0200000001284962f42317232fbf9499086ea66d4a21ae12c1ad1dafd09e7db382164466870000000000ffffffff0150c3000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_previous_transaction_that_the_input_does_not_spend_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001284962f42317232fbf9499086ea66d4a21ae12c1ad1dafd09e7db382164466870000000000ffffffff0150c300000000000016001455555555555555555555555555555555555555550000000000010052020000000198989898989898989898989898989898989898989898989898989898989898980000000000ffffffff0150c30000000000001600143333333333333333333333333333333333333333000000000000',
    },
    err: 'NonWitnessUtxoDoesNotMatchOutpoint',
    msg: 'A full previous transaction with a different id is rejected',
  },
  full_and_witness_utxos_describing_the_same_output_are_accepted: {
    args: {
      psbt: '70736274ff01005202000000012dc300370975c7cee79e3224ea1dfe44a821e35c68b9bd431fc5ec70805a5f640000000000ffffffff0130750000000000001600145555555555555555555555555555555555555555000000000001005202000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000ffffffff01409c00000000000016001444444444444444444444444444444444444444440000000001011f409c00000000000016001444444444444444444444444444444444444444440000',
    },
    msg: 'Full and witness UTXOs of the same spent output are accepted',
    result: {
      inputs: [
        {
          non_witness_utxo: '02000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000ffffffff01409c000000000000160014444444444444444444444444444444444444444400000000',
          witness_utxo: {
            script_pub: '00144444444444444444444444444444444444444444',
            tokens: 40000,
          },
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '02000000012dc300370975c7cee79e3224ea1dfe44a821e35c68b9bd431fc5ec70805a5f640000000000ffffffff013075000000000000160014555555555555555555555555555555555555555500000000',
        },
        {
          type: '00',
          value: '02000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000ffffffff01409c000000000000160014444444444444444444444444444444444444444400000000',
        },
        {
          type: '01',
          value: '409c0000000000001600144444444444444444444444444444444444444444',
        },
      ],
      unsigned_transaction: '02000000012dc300370975c7cee79e3224ea1dfe44a821e35c68b9bd431fc5ec70805a5f640000000000ffffffff013075000000000000160014555555555555555555555555555555555555555500000000',
    },
  },
  a_witness_utxo_with_other_tokens_than_the_full_utxo_is_rejected: {
    args: {
      psbt: '70736274ff01005202000000012dc300370975c7cee79e3224ea1dfe44a821e35c68b9bd431fc5ec70805a5f640000000000ffffffff0130750000000000001600145555555555555555555555555555555555555555000000000001005202000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000ffffffff01409c00000000000016001444444444444444444444444444444444444444440000000001011f419c00000000000016001444444444444444444444444444444444444444440000',
    },
    err: 'WitnessUtxoDoesNotMatchNonWitnessUtxo',
    msg: 'A witness UTXO with tokens unlike the full UTXO is rejected',
  },
  a_witness_utxo_with_another_script_than_the_full_utxo_is_rejected: {
    args: {
      psbt: '70736274ff01005202000000012dc300370975c7cee79e3224ea1dfe44a821e35c68b9bd431fc5ec70805a5f640000000000ffffffff0130750000000000001600145555555555555555555555555555555555555555000000000001005202000000010b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000ffffffff01409c00000000000016001444444444444444444444444444444444444444440000000001011f409c00000000000016001445454545454545454545454545454545454545450000',
    },
    err: 'WitnessUtxoDoesNotMatchNonWitnessUtxo',
    msg: 'A witness UTXO with a script unlike the full UTXO is rejected',
  },
  a_duplicate_output_key_is_rejected: {
    args: {
      psbt: '70736274ff01003f0200000001a761bc70d231afbf215da1123740c58454632f240514d03c2566c441b04a99740000000000ffffffff010000000000000000036a01aa000000000000010001510100015200',
    },
    err: 'UnexpectedDuplicateOutputKey',
    msg: 'A key used twice in an output is rejected',
  },
  an_unsigned_transaction_spending_an_outpoint_twice_is_rejected: {
    args: {
      psbt: '70736274ff010066020000000211111111111111111111111111111111111111111111111111111111111111110000000000ffffffff11111111111111111111111111111111111111111111111111111111111111110000000000ffffffff010000000000000000016a0000000000000000',
    },
    err: 'UnexpectedDuplicateInputOutpoint',
    msg: 'An unsigned transaction spending one outpoint twice is rejected',
  },
  inputs_spending_one_previous_transaction_are_decoded: {
    args: {
      psbt: '70736274ff01006602000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a0000000000010071020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff0288130000000000001600143333333333333333333333333333333333333333701700000000000016001444444444444444444444444444444444444444440000000000010071020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444000000000000',
    },
    msg: 'Inputs spending outputs of one previous transaction are decoded',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
        {
          non_witness_utxo: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '02000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a00000000',
        },
        {
          type: '00',
          value: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
        {
          type: '00',
          value: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
      ],
      unsigned_transaction: '02000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a00000000',
    },
  },
  a_previous_transaction_in_another_serialization_is_decoded: {
    args: {
      psbt: '70736274ff01006602000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a0000000000010071020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444000000000001007f0200000000010112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444010aabababababababababab000000000000',
    },
    msg: 'A previous transaction in another serialization is decoded',
    result: {
      inputs: [
        {
          non_witness_utxo: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
        {
          non_witness_utxo: '0200000000010112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444010aabababababababababab00000000',
        },
      ],
      outputs: [{}],
      pairs: [
        {
          type: '00',
          value: '02000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a00000000',
        },
        {
          type: '00',
          value: '020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff02881300000000000016001433333333333333333333333333333333333333337017000000000000160014444444444444444444444444444444444444444400000000',
        },
        {
          type: '00',
          value: '0200000000010112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444010aabababababababababab00000000',
        },
      ],
      unsigned_transaction: '02000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10100000000ffffffff010000000000000000016a00000000',
    },
  },
  a_shared_previous_transaction_without_the_spent_output_is_rejected: {
    args: {
      psbt: '70736274ff01006602000000024055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10000000000ffffffff4055d13a553e32ef2a0b57353ee83993c65d58d908d9aa009208565154f0c5b10200000000ffffffff010000000000000000016a0000000000010071020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff0288130000000000001600143333333333333333333333333333333333333333701700000000000016001444444444444444444444444444444444444444440000000000010071020000000112121212121212121212121212121212121212121212121212121212121212120000000000ffffffff028813000000000000160014333333333333333333333333333333333333333370170000000000001600144444444444444444444444444444444444444444000000000000',
    },
    err: 'ExpectedSpentOutputInNonWitnessUtxo',
    msg: 'A shared previous transaction without a spent output is rejected',
  },
  a_partial_signature_with_a_zero_sighash_type_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000160014777777777777777777777777777777777777777700000000002202034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa47304402200ec649311b3a9bbc03074f57c5cd1e3428921f3f6d5756c55e1af678e271e9c202203e08f25994791b8dc65bf79ada8e2b5d6a83bf6f6399852776833456997bf734000000',
    },
    err: 'UnexpectedSigHashTypeForPartialSignature',
    msg: 'A partial signature with sighash type 0 is rejected',
  },
  a_partial_signature_with_an_undefined_sighash_type_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000160014777777777777777777777777777777777777777700000000002202034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa47304402200ec649311b3a9bbc03074f57c5cd1e3428921f3f6d5756c55e1af678e271e9c202203e08f25994791b8dc65bf79ada8e2b5d6a83bf6f6399852776833456997bf734040000',
    },
    err: 'UnexpectedSigHashTypeForPartialSignature',
    msg: 'A partial signature with an undefined sighash type is rejected',
  },
  an_output_redeem_script_for_a_witness_output_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000016001477777777777777777777777777777777777777770000000000000100015100',
    },
    err: 'RedeemScriptDoesNotMatchOutput',
    msg: 'An output redeem script for a witness output is rejected',
  },
  an_output_redeem_script_that_is_not_paid_is_rejected: {
    args: {
      psbt: '70736274ff010053020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000017a9143333333333333333333333333333333333333333870000000000000100015100',
    },
    err: 'RedeemScriptDoesNotMatchOutput',
    msg: 'An output redeem script that the output does not pay is rejected',
  },
  an_output_witness_script_that_is_not_paid_is_rejected: {
    args: {
      psbt: '70736274ff01005e020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000022002033333333333333333333333333333333333333333333333333333333333333330000000000000101015100',
    },
    err: 'WitnessScriptDoesNotMatchOutput',
    msg: 'An output witness script that the output does not pay is rejected',
  },
  an_output_nested_redeem_script_that_is_not_a_program_is_rejected: {
    args: {
      psbt: '70736274ff010053020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87000000000000010001510101015100',
    },
    err: 'ExpectedWitnessProgramForNestedRedeemScript',
    msg: 'A nested output redeem script must be a witness program',
  },
  output_scripts_that_the_output_pays_are_decoded: {
    args: {
      psbt: '70736274ff010053020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000017a91472c44f957fc011d97e3406667dca5b1c930c40268700000000000001002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332600101015100',
    },
    msg: 'Output redeem and witness scripts that the output pays are decoded',
    result: {
      inputs: [{}],
      outputs: [
        {
          redeem_script: '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
          witness_script: '51',
        },
      ],
      pairs: [
        {
          type: '00',
          value: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000017a91472c44f957fc011d97e3406667dca5b1c930c40268700000000',
        },
        {
          type: '00',
          value: '00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260',
        },
        {
          type: '01',
          value: '51',
        },
      ],
      unsigned_transaction: '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e80300000000000017a91472c44f957fc011d97e3406667dca5b1c930c40268700000000',
    },
  },
  a_taproot_internal_key_on_a_witness_key_output_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e8030000000000001600147777777777777777777777777777777777777777000000000000010520797979797979797979797979797979797979797979797979797979797979797900',
    },
    err: 'UnexpectedTaprootFieldForNonTaprootOutput',
    msg: 'A taproot internal key on a non taproot output is rejected',
  },
  a_taproot_field_on_a_short_version_1_program_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e8030000000000001651147777777777777777777777777777777777777777000000000000010520797979797979797979797979797979797979797979797979797979797979797900',
    },
    err: 'UnexpectedTaprootFieldForNonTaprootOutput',
    msg: 'A taproot field on a version 1 program of 20 bytes is rejected',
  },
  a_witness_utxo_without_a_script_length_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e8030000000000001600147777777777777777777777777777777777777777000000000001010805000000000000000000',
    },
    err: 'ExpectedScriptPubLengthForWitnessUtxo',
    msg: 'A witness UTXO without a script length is rejected',
  },
  a_witness_utxo_with_a_padded_script_length_is_rejected: {
    args: {
      psbt: '70736274ff010052020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01e803000000000000160014777777777777777777777777777777777777777700000000000101210500000000000000fd1600001422222222222222222222222222222222222222220000',
    },
    err: 'ExpectedScriptPubLengthForWitnessUtxo',
    msg: 'A witness UTXO with a padded script length is rejected',
  },
  a_taproot_field_of_an_input_spending_a_witness_key_is_rejected: {
    args: {
      psbt: '70736274ff01005202000000016274b8a4b394b2d9b97b3c1290fdccfa83f10042f628c4c0d8686d90b41db7490000000000ffffffff0150c30000000000001600147777777777777777777777777777777777777777000000000001011fa086010000000000160014fc7250a211deddc70ee5a2738de5f07817351cef011340abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab0000',
    },
    err: 'UnexpectedTaprootFieldForNonTaprootInput',
    msg: 'A taproot field of an input that spends a key hash is rejected',
  },
  a_taproot_field_of_an_input_spending_a_legacy_output_is_rejected: {
    args: {
      psbt: '70736274ff0100520200000001b67345971a27c2c811ffabafa7a8d71a0cf89f38cc7b5a82790a56080cf0d9e00000000000ffffffff0150c30000000000001600147777777777777777777777777777777777777777000000000001172077777777777777777777777777777777777777777777777777777777777777770100550200000001e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e50000000000ffffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac000000000000',
    },
    err: 'UnexpectedTaprootFieldForNonTaprootInput',
    msg: 'A taproot field of an input spending a legacy output is rejected',
  },
  a_taproot_field_of_an_input_without_a_utxo_is_accepted: {
    args: {
      psbt: '70736274ff01005202000000016274b8a4b394b2d9b97b3c1290fdccfa83f10042f628c4c0d8686d90b41db7490000000000ffffffff0150c30000000000001600147777777777777777777777777777777777777777000000000001172077777777777777777777777777777777777777777777777777777777777777770000',
    },
    msg: 'A taproot field of an input without a known spent output is kept',
    result: {
      inputs: [
        {
          taproot_internal_key: '7777777777777777777777777777777777777777777777777777777777777777',
        },
      ],
      outputs: [
        {},
      ],
      pairs: [
        {
          type: '00',
          value: '02000000016274b8a4b394b2d9b97b3c1290fdccfa83f10042f628c4c0d8686d90b41db7490000000000ffffffff0150c3000000000000160014777777777777777777777777777777777777777700000000',
        },
        {
          type: '17',
          value: '7777777777777777777777777777777777777777777777777777777777777777',
        },
      ],
      unsigned_transaction: '02000000016274b8a4b394b2d9b97b3c1290fdccfa83f10042f628c4c0d8686d90b41db7490000000000ffffffff0150c3000000000000160014777777777777777777777777777777777777777700000000',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, () => {
    if (!!err) {
      throws(() => decodePsbt(args), new Error(err), 'Got expected error');

      return;
    }

    const res = JSON.parse(JSON.stringify(decodePsbt(args)));

    strictSame(res, result, 'Got expected result');

    return;
  });
});
