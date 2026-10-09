const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const hash256 = require('./hash256');
const {tokensAsBuffer} = require('./../transactions');
const {uint32AsBuffer} = require('./../transactions');

const anyoneCanPayFlag = 0x80;
const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const outputTypeMask = 0x1f;
const sigHashNone = 2;
const sigHashSingle = 3;
const zeroHash = Buffer.alloc(32);

/** Calculate the BIP 143 signature hash of a version 0 witness input

  {
    hashes: {
      outputs: <Hash of All Outputs Buffer Object>
      prevouts: <Hash of All Spent Outpoints Buffer Object>
      sequences: <Hash of All Input Sequences Buffer Object>
    }
    parts: {
      locktime: <Serialized Lock Time Buffer Object>
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
      version: <Serialized Version Buffer Object>
    }
    script: <Script Code Hex String>
    sighash: <Signature Hash Type Number>
    tokens: <Spent Output Tokens Number>
    vin: <Signing Input Index Number>
  }

  @returns
  {
    hash: <Signature Hash Buffer Object>
  }
*/
module.exports = ({hashes, parts, script, sighash, tokens, vin}) => {
  const outputType = sighash & outputTypeMask;
  const scriptCode = hexAsBuffer(script);

  const isAnyoneCanPay = !!(sighash & anyoneCanPayFlag);
  const isSingle = outputType === sigHashSingle;

  const isAllOutputs = !isSingle && outputType !== sigHashNone;
  const single = isSingle ? parts.outputs[vin] : undefined;

  // Outputs are committed to as all outputs, as one output, or not at all
  let outputsHash = zeroHash;

  if (isAllOutputs) {
    outputsHash = hashes.outputs;
  } else if (!!single) {
    outputsHash = hash256({data: single});
  }

  const preimage = Buffer.concat([
    parts.version,
    isAnyoneCanPay ? zeroHash : hashes.prevouts,
    !isAnyoneCanPay && isAllOutputs ? hashes.sequences : zeroHash,
    parts.outpoints[vin],
    encode(scriptCode.length),
    scriptCode,
    tokensAsBuffer({tokens}),
    parts.sequences[vin],
    outputsHash,
    parts.locktime,
    uint32AsBuffer({number: sighash}),
  ]);

  return {hash: hash256({data: preimage})};
};
