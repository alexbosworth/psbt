const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const tokensAsNumber = require('./../../psbts/tokens_as_number');

// Test scenarios
const tests = {
  a_tokens_value_is_decoded_as_a_number: {
    args: {value: Buffer.from('00e1f50500000000', 'hex')},
    msg: 'A tokens value is decoded as a number',
    result: {tokens: 100000000},
  },
  a_value_that_is_too_short_to_decode_is_rejected: {
    args: {value: Buffer.from('00e1f505', 'hex')},
    err: 'ExpectedValidTokensNumber',
    msg: 'A value that is too short to decode is rejected',
  },
  a_value_above_the_maximum_safe_number_is_rejected: {
    args: {value: Buffer.from('ffffffffffffffff', 'hex')},
    err: 'ExpectedValidTokensNumber',
    msg: 'A value above the maximum safe number is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => tokensAsNumber(args), new Error(err));

      return end();
    }

    equal(tokensAsNumber(args), result.tokens);

    return end();
  });
});
