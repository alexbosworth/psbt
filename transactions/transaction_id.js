const {idForTransactionComponents} = require('@alexbosworth/blockchain');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

/** Get the id of a transaction from its parsed components

  {
    inputs: [{
      id: <Spending Transaction Id Hex String>
      script: <ScriptSig Script Hex String>
      sequence: <Sequence Number>
      vout: <Spending Transaction Output Index Number>
    }]
    locktime: <Timelock nLockTime Number>
    outputs: [{
      script: <ScriptPub Script Hex String>
      tokens: <Tokens Count Number>
    }]
    version: <Version Number>
  }

  @returns
  {
    id: <Transaction Id Hex String>
  }
*/
module.exports = ({inputs, locktime, outputs, version}) => {
  return idForTransactionComponents({
    locktime,
    version,
    inputs: inputs.map(n => ({
      hash: hexAsBuffer(n.id).reverse(),
      script: hexAsBuffer(n.script),
      sequence: n.sequence,
      vout: n.vout,
    })),
    outputs: outputs.map(n => ({
      script: hexAsBuffer(n.script),
      tokens: n.tokens,
    })),
  });
};
