const {equal} = require('node:assert').strict;
const test = require('node:test');

const {pushData} = require('./../../script');

const {concat} = Buffer;

// Test scenarios
const tests = {
  a_hex_string_is_encoded_as_a_small_data_push: {
    args: {encode: 'ab'},
    msg: 'A hex string is encoded as a small data push',
    result: {push: Buffer.from('01ab', 'hex')},
  },
  an_empty_data_element_is_encoded_as_a_zero_length_push: {
    args: {data: Buffer.alloc(0)},
    msg: 'An empty data element is encoded as a zero length push',
    result: {push: Buffer.from('00', 'hex')},
  },
  data_at_the_direct_push_limit_uses_a_length_byte: {
    args: {data: Buffer.alloc(75, 1)},
    msg: 'Data at the direct push limit uses a length byte',
    result: {push: concat([Buffer.from([75]), Buffer.alloc(75, 1)])},
  },
  data_over_the_direct_push_limit_uses_op_pushdata1: {
    args: {data: Buffer.alloc(76, 2)},
    msg: 'Data over the direct push limit uses OP_PUSHDATA1',
    result: {push: concat([Buffer.from([76, 76]), Buffer.alloc(76, 2)])},
  },
  data_at_the_op_pushdata1_limit_uses_op_pushdata1: {
    args: {data: Buffer.alloc(255, 3)},
    msg: 'Data at the OP_PUSHDATA1 limit uses OP_PUSHDATA1',
    result: {push: concat([Buffer.from([76, 255]), Buffer.alloc(255, 3)])},
  },
  data_over_the_op_pushdata1_limit_uses_op_pushdata2: {
    args: {data: Buffer.alloc(256, 4)},
    msg: 'Data over the OP_PUSHDATA1 limit uses OP_PUSHDATA2',
    result: {push: concat([Buffer.from([77, 0, 1]), Buffer.alloc(256, 4)])},
  },
  data_at_the_op_pushdata2_limit_uses_op_pushdata2: {
    args: {data: Buffer.alloc(65535, 5)},
    msg: 'Data at the OP_PUSHDATA2 limit uses OP_PUSHDATA2',
    result: {
      push: concat([Buffer.from([77, 255, 255]), Buffer.alloc(65535, 5)]),
    },
  },
  data_over_the_op_pushdata2_limit_uses_op_pushdata4: {
    args: {data: Buffer.alloc(65536, 6)},
    msg: 'Data over the OP_PUSHDATA2 limit uses OP_PUSHDATA4',
    result: {
      push: concat([Buffer.from([78, 0, 0, 1, 0]), Buffer.alloc(65536, 6)]),
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg, result}) => {
  return test(msg, (t, end) => {
    equal(pushData(args).toString('hex'), result.push.toString('hex'), msg);

    return end();
  });
});
