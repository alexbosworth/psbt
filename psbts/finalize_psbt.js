const updatePsbt = require('./update_psbt');

/** Finalize the inputs of a PSBT
  {
    ecp: <ECPair Object>
    psbt: <BIP 174 Encoded PSBT Hex String>
  }

  @throws
  <Finalize PSBT Error>

  @returns
  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }
*/
module.exports = ({ecp, psbt}) => {
  return updatePsbt({ecp, psbt, is_final: true});
};
