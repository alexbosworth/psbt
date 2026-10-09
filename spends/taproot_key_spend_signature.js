const {signSchnorr} = require('tiny-secp256k1');

const {defaultTapSigHashType} = require('./../signatures/constants');
const {tapSigHashTypes} = require('./../psbts/constants');
const {taprootSignatureHash} = require('./../sighash');

const bufferAsHex = buffer => buffer.toString('hex');

/** Sign a taproot input with a key spend signature

  An input is signed with its sighash type, or with the default sighash type
  when it has none. A signature of the default sighash type is 64 bytes, and
  a signature of another sighash type ends with its sighash type.

  {
    hashes: {
      [amounts]: <Hash of All Spent Output Amounts Buffer Object>
      outputs: <Hash of All Outputs Buffer Object>
      prevouts: <Hash of All Spent Outpoints Buffer Object>
      [scripts]: <Hash of All Spent Output Scripts Buffer Object>
      sequences: <Hash of All Input Sequences Buffer Object>
    }
    parts: {
      locktime: <Serialized Lock Time Buffer Object>
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
      version: <Serialized Version Buffer Object>
    }
    private_key: <Private Key of the Output Key Buffer Object>
    [sighash_type]: <Input Sighash Type Number>
    spent: {
      script: <Spent Output Script Hex String>
      tokens: <Spent Output Tokens Number>
    }
    vin: <Input Index Number>
  }

  @throws
  <ExpectedOutputForInputSigningWithSigHashSingle Error>
  <ExpectedSpentOutputsOfInputsToHashTaprootSignature Error>
  <UnsupportedSigHashTypeToSign Error>

  @returns
  {
    signature: <Key Spend Signature Hex String>
  }
*/
module.exports = args => {
  const hasSigHash = args.sighash_type !== undefined;

  const sighash = hasSigHash ? args.sighash_type : defaultTapSigHashType;

  const isDefault = sighash === defaultTapSigHashType;

  // A taproot input is signed with the default or a defined sighash type
  if (!isDefault && !tapSigHashTypes.includes(sighash)) {
    throw new Error('UnsupportedSigHashTypeToSign');
  }

  const {hash} = taprootSignatureHash({
    sighash,
    hashes: args.hashes,
    parts: args.parts,
    spent: args.spent,
    vin: args.vin,
  });

  const signature = Buffer.from(signSchnorr(hash, args.private_key));

  // Exit early when the signature has the default sighash type
  if (isDefault) {
    return {signature: bufferAsHex(signature)};
  }

  const sighashFlag = Buffer.from([sighash]);

  return {signature: bufferAsHex(Buffer.concat([signature, sighashFlag]))};
};
