const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const encodePsbt = require('./../../psbts/encode_psbt');

const asBuffer = hex => Buffer.from(hex, 'hex');
const separator = {separator: true};
const tx = '020000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff010000000000000000016a00000000';

const transaction = {type: asBuffer('00'), value: asBuffer(tx)};

// Encoded PSBT bytes before and after the global fields of a test
const start = `70736274ff01003d${tx}`;
const end = '000000';

// Test scenarios
const tests = {
  key_value_pairs_are_encoded_as_a_psbt: {
    args: {pairs: [transaction, separator, separator, separator]},
    msg: 'Key value pairs are encoded as a psbt',
    result: {psbt: `${start}${end}`},
  },
  pairs_are_expected_to_be_an_array: {
    args: {pairs: null},
    err: 'ExpectedKeyValuePairsToEncode',
    msg: 'Pairs are expected to be an array',
  },
  an_entry_that_is_not_an_object_is_rejected: {
    args: {pairs: [null]},
    err: 'ExpectedKeyAndValueForPsbtPair',
    msg: 'An entry that is not an object is rejected',
  },
  an_entry_without_a_key_or_value_is_rejected: {
    args: {pairs: [{}]},
    err: 'ExpectedKeyAndValueForPsbtPair',
    msg: 'An entry that is not a separator needs a key and a value',
  },
  a_key_without_a_value_is_rejected: {
    args: {pairs: [{type: asBuffer('f0')}]},
    err: 'ExpectedKeyAndValueForPsbtPair',
    msg: 'A key without a value is rejected',
  },
  a_key_that_is_not_bytes_is_rejected: {
    args: {pairs: [{type: 'f0', value: asBuffer('01')}]},
    err: 'ExpectedBytesForPsbtKey',
    msg: 'A key that is not bytes is rejected',
  },
  a_value_that_is_not_bytes_is_rejected: {
    args: {pairs: [{type: asBuffer('f0'), value: '01'}]},
    err: 'ExpectedBytesForPsbtValue',
    msg: 'A value that is not bytes is rejected',
  },
  an_empty_key_is_rejected: {
    args: {pairs: [{type: Buffer.alloc(0), value: asBuffer('00')}]},
    err: 'ExpectedNonEmptyKeyForPsbtField',
    msg: 'A field with an empty key is rejected',
  },
  a_field_with_an_empty_value_is_encoded: {
    args: {
      pairs: [
        transaction,
        {type: asBuffer('f0'), value: Buffer.alloc(0)},
        separator,
        separator,
        separator,
      ],
    },
    msg: 'A field with an empty value is encoded',
    result: {psbt: `${start}01f000${end}`},
  },
  a_key_given_as_a_uint8_array_is_encoded: {
    args: {
      pairs: [
        transaction,
        {type: new Uint8Array([0xf0]), value: asBuffer('01')},
        separator,
        separator,
        separator,
      ],
    },
    msg: 'A key given as a Uint8Array is encoded',
    result: {psbt: `${start}01f00101${end}`},
  },
  a_separator_with_a_key_is_rejected: {
    args: {pairs: [{separator: true, type: asBuffer('f0')}]},
    err: 'UnexpectedKeyOrValueForSeparator',
    msg: 'A separator with a key is rejected',
  },
  a_separator_with_a_value_is_rejected: {
    args: {pairs: [{separator: true, value: asBuffer('00')}]},
    err: 'UnexpectedKeyOrValueForSeparator',
    msg: 'A separator with a value is rejected',
  },
  a_separator_with_a_key_and_value_is_rejected: {
    args: {
      pairs: [{separator: true, type: asBuffer('f0'), value: asBuffer('00')}],
    },
    err: 'UnexpectedKeyOrValueForSeparator',
    msg: 'A separator with a key and value is rejected',
  },
  a_key_whose_type_number_is_cut_off_is_rejected: {
    args: {pairs: [{type: asBuffer('fd'), value: asBuffer('00')}]},
    err: 'InvalidPsbtKeyTypeEncoding',
    msg: 'A key whose type number is cut off is rejected',
  },
  a_key_whose_type_number_is_padded_is_rejected: {
    args: {pairs: [{type: asBuffer('fd0100'), value: asBuffer('00')}]},
    err: 'InvalidPsbtKeyTypeEncoding',
    msg: 'A key whose type number uses more bytes than necessary is rejected',
  },
  a_key_with_a_type_beyond_the_safe_number_limit_is_encoded: {
    args: {
      pairs: [
        transaction,
        {type: asBuffer('ff0000000000000001'), value: asBuffer('01')},
        separator,
        separator,
        separator,
      ],
    },
    msg: 'A key with a type number beyond the safe number limit is encoded',
    result: {psbt: `${start}09ff00000000000000010101${end}`},
  },
  a_key_repeated_with_a_different_value_is_rejected: {
    args: {
      pairs: [
        {type: asBuffer('f0'), value: asBuffer('01')},
        {type: asBuffer('f0'), value: asBuffer('02')},
      ],
    },
    err: 'UnexpectedDuplicateKeyInPsbtSection',
    msg: 'A key repeated in a section with a different value is rejected',
  },
  a_key_repeated_with_the_same_value_is_rejected: {
    args: {
      pairs: [
        {type: asBuffer('f0'), value: asBuffer('01')},
        {type: asBuffer('f0'), value: asBuffer('01')},
      ],
    },
    err: 'UnexpectedDuplicateKeyInPsbtSection',
    msg: 'A key repeated in a section with the same value is rejected',
  },
  a_key_in_different_sections_is_encoded: {
    args: {
      pairs: [
        transaction,
        {type: asBuffer('f0'), value: asBuffer('01')},
        separator,
        {type: asBuffer('f0'), value: asBuffer('02')},
        separator,
        {type: asBuffer('f0'), value: asBuffer('03')},
        separator,
      ],
    },
    msg: 'The same key in different sections is encoded',
    result: {psbt: `${start}01f001010001f001020001f0010300`},
  },
  keys_of_the_same_type_are_encoded: {
    args: {
      pairs: [
        transaction,
        {type: asBuffer('f001'), value: asBuffer('01')},
        {type: asBuffer('f002'), value: asBuffer('02')},
        separator,
        separator,
        separator,
      ],
    },
    msg: 'Different keys of the same type in a section are encoded',
    result: {psbt: `${start}02f001010102f0020102${end}`},
  },
  pairs_without_a_transaction_are_rejected: {
    args: {pairs: []},
    err: 'ExpectedUnsignedTransaction',
    msg: 'Pairs without an unsigned transaction are not a PSBT',
  },
  pairs_without_every_section_are_rejected: {
    args: {pairs: [transaction, separator, separator]},
    err: 'ExpectedAdditionalOutputs',
    msg: 'Pairs without a section for every output are not a PSBT',
  },
  pairs_that_are_not_valid_fields_are_rejected: {
    args: {
      pairs: [
        transaction,
        separator,
        {type: asBuffer('03'), value: asBuffer('01')},
        separator,
        separator,
      ],
    },
    err: 'UnexpectedSigHashTypeByteLength',
    msg: 'Pairs with a field value that is not valid are not a PSBT',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => encodePsbt(args), new Error(err));

      return end();
    }

    equal(encodePsbt(args).psbt, result.psbt);

    return end();
  });
});
