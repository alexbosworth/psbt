const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {createPsbt} = require('./../../');

const longHex = 'ab'.repeat(1e7);

// Test scenarios
const tests = {
  an_array_of_outputs_is_expected: {
    args: {utxos: []},
    err: 'ExpectedTransactionOutputsForNewPsbt',
    msg: 'An array of outputs is expected',
  },
  an_array_of_utxos_is_expected: {
    args: {outputs: []},
    err: 'ExpectedTransactionInputsForNewPsbt',
    msg: 'An array of utxos is expected',
  },
  a_creator_creating_a_psbt_for_a_transaction: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
        {
          script: '001400aea9a2e5f0f876a588df5546e8742d1d87008f',
          tokens: 100000000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          vout: 1,
        },
      ],
    },
    msg: 'A creator creating a PSBT for a transaction',
    result: {
      psbt: '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000',
    },
  },
  a_sequence_on_a_later_input_stays_on_that_input: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          sequence: 4294967293,
          vout: 1,
        },
      ],
    },
    msg: 'A sequence set on a later input is applied to that input',
    result: {
      psbt: '70736274ff01007b020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000fdffffff0170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d0000000000000000',
    },
  },
  a_zero_sequence_is_kept: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          sequence: 0,
          vout: 0,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          vout: 1,
        },
      ],
    },
    msg: 'A zero sequence is kept instead of being replaced by the default',
    result: {
      psbt: '70736274ff01007b020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd75000000000000000000838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d0000000000000000',
    },
  },
  a_timelock_enables_sequences_without_a_setting: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      timelock: 800000,
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          vout: 1,
          sequence: 4294967293,
        },
      ],
    },
    msg: 'A timelock gives inputs without a sequence a timelock enabling one',
    result: {
      psbt: '70736274ff01007b020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000feffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000fdffffff0170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00350c0000000000',
    },
  },
  a_timelock_with_one_final_sequence_is_allowed: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      timelock: 800000,
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
          sequence: 4294967295,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          vout: 1,
        },
      ],
    },
    msg: 'A timelock is allowed when an unspecified input sequence enables it',
    result: {
      psbt: '70736274ff01007b020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000feffffff0170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00350c0000000000',
    },
  },
  a_timelock_disabled_on_every_input_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      timelock: 800000,
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
          sequence: 4294967295,
        },
        {
          id: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
          vout: 1,
          sequence: 4294967295,
        },
      ],
    },
    err: 'ExpectedNonFinalSequenceForTimelockToTakeEffect',
    msg: 'A timelock that every input sequence disables is rejected',
  },
  a_version_zero_is_kept: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
      version: 0,
    },
    msg: 'A zero transaction version is kept instead of using the default',
    result: {
      psbt: '70736274ff010052000000000158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff0170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00000000000000',
    },
  },
  a_missing_output_index_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
        },
      ],
    },
    err: 'ExpectedOutputIndexNumberForNewPsbtUtxo',
    msg: 'A utxo without an output index is rejected',
  },
  a_psbt_without_inputs_is_created: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [],
    },
    msg: 'A PSBT without inputs and with one output is created',
    result: {
      psbt: '70736274ff01002902000000000170aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d000000000000',
    },
  },
  a_transaction_id_buffer_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: Buffer.from('75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858', 'hex'), vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A transaction id given as a buffer is rejected',
  },
  a_transaction_id_array_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: [...Buffer.from('75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858', 'hex')], vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A transaction id given as an array is rejected',
  },
  a_short_transaction_id_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae8', vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A transaction id that is too short is rejected',
  },
  a_long_transaction_id_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae85800', vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A transaction id that is too long is rejected',
  },
  a_transaction_id_with_non_hex_characters_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae8zz', vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A transaction id with non-hex characters is rejected',
  },
  a_missing_transaction_id_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [{id: undefined, vout: 0}],
    },
    err: 'ExpectedTransactionIdHexStringForNewPsbtUtxo',
    msg: 'A utxo without a transaction id is rejected',
  },
  a_fractional_output_index_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 1.9,
        },
      ],
    },
    err: 'ExpectedOutputIndexNumberForNewPsbtUtxo',
    msg: 'A fractional output index is rejected',
  },
  a_fractional_sequence_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
          sequence: 1.9,
        },
      ],
    },
    err: 'ExpectedValidSequenceNumberForNewPsbtUtxo',
    msg: 'A fractional sequence is rejected',
  },
  an_out_of_range_sequence_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
          sequence: 4294967296,
        },
      ],
    },
    err: 'ExpectedValidSequenceNumberForNewPsbtUtxo',
    msg: 'A sequence beyond 32 bits is rejected',
  },
  fractional_tokens_are_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 1.9,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedNonNegativeIntegerTokensForNewPsbtOutput',
    msg: 'Fractional output tokens are rejected',
  },
  negative_tokens_are_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: -1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedNonNegativeIntegerTokensForNewPsbtOutput',
    msg: 'Negative output tokens are rejected',
  },
  a_fractional_timelock_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      timelock: 1.9,
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedValidTimelockNumberForNewPsbt',
    msg: 'A fractional timelock is rejected',
  },
  a_fractional_version_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 149990000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
      version: 1.9,
    },
    err: 'ExpectedValidVersionNumberForNewPsbt',
    msg: 'A fractional version is rejected',
  },
  a_missing_output_script_is_rejected: {
    args: {
      outputs: [
        {
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedHexOutputScriptForNewPsbtOutput',
    msg: 'An output without a script is rejected',
  },
  an_output_script_that_is_not_whole_bytes_is_rejected: {
    args: {
      outputs: [
        {
          script: 'abc',
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedHexOutputScriptForNewPsbtOutput',
    msg: 'An output script that is not whole bytes of hex is rejected',
  },
  an_output_script_with_non_hex_characters_is_rejected: {
    args: {
      outputs: [
        {
          script: '51zz',
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedHexOutputScriptForNewPsbtOutput',
    msg: 'An output script with characters that are not hex is rejected',
  },
  a_very_long_output_script_that_is_not_hex_is_rejected: {
    args: {
      outputs: [
        {
          script: `${longHex}x`,
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedHexOutputScriptForNewPsbtOutput',
    msg: 'A very long output script that is not hex is rejected',
  },
  an_output_script_given_as_a_buffer_is_rejected: {
    args: {
      outputs: [
        {
          script: Buffer.from('51', 'hex'),
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'ExpectedHexOutputScriptForNewPsbtOutput',
    msg: 'An output script given as a buffer is rejected',
  },
  an_empty_output_script_is_allowed: {
    args: {
      outputs: [
        {
          script: '',
          tokens: 0,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    msg: 'An empty output script is allowed',
    result: {
      psbt: '70736274ff01003c020000000158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff0100000000000000000000000000000000',
    },
  },
  outputs_sending_more_than_every_bitcoin_are_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 1100000000000000,
        },
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 1000000000000001,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    err: 'UnexpectedOutputTokensAboveMaxMoneyForNewPsbt',
    msg: 'Outputs sending more than 21 million bitcoin are rejected',
  },
  an_output_sending_every_bitcoin_is_allowed: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 2100000000000000,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 0,
        },
      ],
    },
    msg: 'An output sending exactly 21 million bitcoin is allowed',
    result: {
      psbt: '70736274ff010052020000000158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff010040075af0750700160014d85c2b71d0060b09c9886aeb815e50991dda124d00000000000000',
    },
  },
  an_outpoint_spent_twice_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 1,
        },
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 1,
        },
      ],
    },
    err: 'UnexpectedDuplicateOutpointForNewPsbtUtxo',
    msg: 'An outpoint that is spent twice is rejected',
  },
  an_outpoint_spent_twice_in_another_case_is_rejected: {
    args: {
      outputs: [
        {
          script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
          tokens: 1,
        },
      ],
      utxos: [
        {
          id: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
          vout: 1,
        },
        {
          id: '75DDABB27B8845F5247975C8A5BA7C6F336C4570708EBE230CAF6DB5217AE858',
          vout: 1,
        },
      ],
    },
    err: 'UnexpectedDuplicateOutpointForNewPsbtUtxo',
    msg: 'An outpoint spent twice with an id in another case is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => createPsbt(args), new Error(err));

      return end();
    }

    const {psbt} = createPsbt(args);

    equal(psbt, result.psbt);

    return end();
  });
});
