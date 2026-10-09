const {createHash} = require('node:crypto');

const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const {tokensAsBuffer} = require('./../transactions');
const {uint32AsBuffer} = require('./../transactions');

const anyoneCanPayFlag = 0x80;
const encode = number => numberAsCompactInt({number}).encoded;
const epoch = Buffer.alloc(1);
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const keySpendType = Buffer.alloc(1);
const outputTypeMask = 3;
const sha256 = data => createHash('sha256').update(data).digest();
const sigHashNone = 2;
const sigHashSingle = 3;
const tag = Buffer.from('TapSighash');

/** Calculate the BIP 341 signature hash of a taproot key spend without annex

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
    sighash: <Signature Hash Type Number>
    spent: {
      script: <Spent Output Script Hex String>
      tokens: <Spent Output Tokens Number>
    }
    vin: <Signing Input Index Number>
  }

  @throws
  <ExpectedOutputForInputSigningWithSigHashSingle Error>
  <ExpectedSpentOutputsOfInputsToHashTaprootSignature Error>

  @returns
  {
    hash: <Signature Hash Buffer Object>
  }
*/
module.exports = ({hashes, parts, sighash, spent, vin}) => {
  const outputType = sighash & outputTypeMask;

  const isAnyoneCanPay = !!(sighash & anyoneCanPayFlag);
  const isNone = outputType === sigHashNone;
  const isSingle = outputType === sigHashSingle;

  // Signing for one output needs an output at the input's index
  if (isSingle && !parts.outputs[vin]) {
    throw new Error('ExpectedOutputForInputSigningWithSigHashSingle');
  }

  // A signature for every input commits to the outputs that they spend
  if (!isAnyoneCanPay && (!hashes.amounts || !hashes.scripts)) {
    throw new Error('ExpectedSpentOutputsOfInputsToHashTaprootSignature');
  }

  const elements = [
    epoch,
    Buffer.from([sighash]),
    parts.version,
    parts.locktime,
  ];

  // Other inputs are committed to unless anyone can pay
  if (!isAnyoneCanPay) {
    elements.push(
      hashes.prevouts,
      hashes.amounts,
      hashes.scripts,
      hashes.sequences,
    );
  }

  // All of the outputs are committed to unless signing for none or for one
  if (!isNone && !isSingle) {
    elements.push(hashes.outputs);
  }

  elements.push(keySpendType);

  // The signing input is committed to by its index or by its own details
  if (isAnyoneCanPay) {
    const script = hexAsBuffer(spent.script);

    elements.push(
      parts.outpoints[vin],
      tokensAsBuffer({tokens: spent.tokens}),
      encode(script.length),
      script,
      parts.sequences[vin],
    );
  } else {
    elements.push(uint32AsBuffer({number: vin}));
  }

  // Signing for one output commits to the output at the input's index
  if (isSingle) {
    elements.push(sha256(parts.outputs[vin]));
  }

  // The signature hash is a hash tagged as a BIP 341 signature hash
  const tagHash = sha256(tag);

  return {hash: sha256(Buffer.concat([tagHash, tagHash, ...elements]))};
};
