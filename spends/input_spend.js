const {isP2shScript} = require('./../utxos');
const scriptSpend = require('./script_spend');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Determine how an input spends its output, to know how to sign it

  {
    input: {
      [redeem_script]: <Redeem Script Hex String>
      [witness_script]: <Witness Script Hex String>
    }
    spent: {
      [script]: <Spent Output Script Hex String>
      [tokens]: <Spent Output Tokens Number>
    }
  }

  @returns
  {
    [is_witness]: <Input Is Signed as a Version 0 Witness Input Bool>
    [script]: <Script Code Hex String>
    [tokens]: <Spent Output Tokens Number>
  }
*/
module.exports = ({input, spent}) => {
  const redeem = input.redeem_script;
  const witness = input.witness_script;

  // Without a spent output there are only the scripts of the input to go by
  if (!spent.script && redeem !== undefined) {
    return scriptSpend({witness, script: redeem});
  }

  if (!spent.script && witness !== undefined) {
    return {is_witness: true, script: witness};
  }

  if (!spent.script) {
    return {};
  }

  const isP2sh = isP2shScript({script: hexAsBuffer(spent.script)});

  // A P2SH output is spent with the redeem script that it pays to
  if (isP2sh && redeem === undefined) {
    return {};
  }

  const spend = scriptSpend({witness, script: isP2sh ? redeem : spent.script});

  // Exit early when the spent script is not a kind that can be signed
  if (!spend.script) {
    return {};
  }

  return {
    is_witness: spend.is_witness,
    script: spend.script,
    tokens: spent.tokens,
  };
};
