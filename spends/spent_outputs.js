const {componentsOfTransaction} = require('@alexbosworth/blockchain');

const outputsOf = hex => componentsOfTransaction({transaction: hex}).outputs;

/** Get the outputs that the inputs of a PSBT spend, from their UTXOs

  Inputs that spend from the same full previous transaction share its parsed
  outputs

  {
    inputs: [{
      [non_witness_utxo]: <Non-Witness UTXO Transaction Hex String>
      [witness_utxo]: {
        script_pub: <Spent Output Script Hex String>
        tokens: <Spent Output Tokens Number>
      }
    }]
    transaction: {
      inputs: [{
        id: <Spent Transaction Id Hex String>
        vout: <Spent Output Index Number>
      }]
    }
  }

  @returns
  {
    spent: [{
      [script]: <Spent Output Script Hex String>
      [tokens]: <Spent Output Tokens Number>
    }]
  }
*/
module.exports = ({inputs, transaction}) => {
  const fundings = new Map();

  const spent = inputs.map((input, vin) => {
    const {id, vout} = transaction.inputs[vin];

    // The witness UTXO is used when present, it avoids parsing a transaction
    if (!!input.witness_utxo) {
      const {tokens} = input.witness_utxo;

      return {tokens, script: input.witness_utxo.script_pub};
    }

    // Without any UTXO, there is no known spent output
    if (!input.non_witness_utxo) {
      return {};
    }

    // Inputs that spend from the same transaction share its parsed outputs
    if (!fundings.has(id)) {
      fundings.set(id, outputsOf(input.non_witness_utxo));
    }

    // The decoder checked that the full transaction has the spent output
    return fundings.get(id)[vout];
  });

  return {spent};
};
