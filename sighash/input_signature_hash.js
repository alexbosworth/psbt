const legacySignatureHash = require('./legacy_signature_hash');
const v0SignatureHash = require('./v0_signature_hash');

/** Calculate the hash that the signatures of an input sign

  {
    hashes: {
      outputs: <Hash of All Outputs Buffer Object>
      prevouts: <Hash of All Spent Outpoints Buffer Object>
      sequences: <Hash of All Input Sequences Buffer Object>
    }
    [is_witness]: <Input Is Signed as a Version 0 Witness Input Bool>
    parts: {
      locktime: <Serialized Lock Time Buffer Object>
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
      version: <Serialized Version Buffer Object>
    }
    script: <Script Code Hex String>
    sighash: <Signature Hash Type Number>
    [tokens]: <Spent Output Tokens Number>
    vin: <Signing Input Index Number>
  }

  @returns
  {
    hash: <Signature Hash Buffer Object>
  }
*/
module.exports = args => {
  // Witness inputs are signed with BIP 143 signature hashes
  if (!!args.is_witness) {
    return v0SignatureHash({
      hashes: args.hashes,
      parts: args.parts,
      script: args.script,
      sighash: args.sighash,
      tokens: args.tokens,
      vin: args.vin,
    });
  }

  return legacySignatureHash({
    parts: args.parts,
    script: args.script,
    sighash: args.sighash,
    vin: args.vin,
  });
};
