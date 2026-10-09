const {deepStrictEqual} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const psbtSections = require('./../../psbts/psbt_sections');

const asHex = ({sections}) => sections.map(section => {
  return section.map(n => [n.type.toString('hex'), n.value.toString('hex')]);
});

// Test scenarios
const tests = {
  a_psbt_is_split_into_its_sections: {
    args: {psbt: '70736274ff0100020000010102ff03000001040000'},
    msg: 'A PSBT is split into the pairs of each section, even empty ones',
    result: [[['00', '0000'], ['01', 'ff03']], [], [['04', '']]],
  },
  a_psbt_with_a_cut_off_value_is_rejected: {
    args: {psbt: '70736274ff01000500'},
    err: 'ExpectedMoreBytesForPsbtKeyOrValue',
    msg: 'A PSBT with a value cut off before its stated length is rejected',
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, (t, end) => {
    if (!!err) {
      throws(() => psbtSections(args), new Error(err));

      return end();
    }

    deepStrictEqual(asHex(psbtSections(args)), result);

    return end();
  });
});
