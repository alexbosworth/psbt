/** Get the output that an input spends from the funding records of the input

  {
    [known]: [{
      script: <Output Script Hex String>
      tokens: <Output Tokens Number>
    }]
    [supplied]: [{
      script: <Output Script Hex String>
      tokens: <Output Tokens Number>
    }]
    vout: <Spent Output Index Number>
    [witness_utxo]: {
      script_pub: <Spent Output Script Hex String>
      tokens: <Spent Output Tokens Number>
    }
  }

  @throws
  <ExpectedSpentOutputInSpendingTransaction Error>

  @returns
  {
    [script]: <Spent Output Script Hex String>
    [tokens]: <Spent Output Tokens Number>
  }
*/
module.exports = ({known, supplied, vout, witness_utxo}) => {
  // A supplied funding transaction must have the output that is being spent
  if (!!supplied && !supplied[vout]) {
    throw new Error('ExpectedSpentOutputInSpendingTransaction');
  }

  if (!!supplied) {
    return supplied[vout];
  }

  if (!!witness_utxo) {
    return {script: witness_utxo.script_pub, tokens: witness_utxo.tokens};
  }

  // The decoder checked that a funding transaction has the output spent
  if (!!known) {
    return known[vout];
  }

  return {};
};
