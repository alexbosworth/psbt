const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {decodePsbt} = require('./../../');

// Test scenarios
const tests = {
  empty_inputs_and_outputs_are_separate_objects: {
    args: {
      psbt: '70736274ff010070020000000211111111111111111111111111111111111111111111111111111111111111110000000000ffffffff22222222222222222222222222222222222222222222222222222222222222220100000000ffffffff02e803000000000000016ae803000000000000016a000000000000000000',
    },
    msg: 'Empty inputs and outputs are separate objects',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, msg}) => {
  return test(msg, () => {
    const decoded = decodePsbt(args);

    decoded.inputs[0].note = 'changed';
    decoded.outputs[0].note = 'changed';

    strictSame(decoded.inputs[1], {}, 'The second input is unchanged');
    strictSame(decoded.outputs[1], {}, 'The second output is unchanged');

    return;
  });
});
