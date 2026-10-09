const {numberAsCompactInt} = require('@alexbosworth/blockchain');

const hash256 = require('./hash256');
const {uint32AsBuffer} = require('./../transactions');

const anyoneCanPayFlag = 0x80;
const blankOutput = Buffer.from('ffffffffffffffff00', 'hex');
const emptyScript = Buffer.alloc(1);
const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const noOutputs = 0;
const oneHash = Buffer.from('01'.padEnd(64, '0'), 'hex');
const outputTypeMask = 0x1f;
const sigHashNone = 2;
const sigHashSingle = 3;
const singleInput = 1;
const zeroSequence = Buffer.alloc(4);

/** Calculate the signature hash of a legacy input

  The script code is expected to have no code separators

  Signing one output when there is no output at the input's index signs the
  number 1, the historical rule that Bitcoin checks these signatures with

  {
    parts: {
      locktime: <Serialized Lock Time Buffer Object>
      outpoints: [<Serialized Spent Outpoint Buffer Object>]
      outputs: [<Serialized Output Buffer Object>]
      sequences: [<Serialized Input Sequence Buffer Object>]
      version: <Serialized Version Buffer Object>
    }
    script: <Script Code Hex String>
    sighash: <Signature Hash Type Number>
    vin: <Signing Input Index Number>
  }

  @returns
  {
    hash: <Signature Hash Buffer Object>
  }
*/
module.exports = ({parts, script, sighash, vin}) => {
  const inputs = [];
  const outputType = sighash & outputTypeMask;
  const scriptCode = hexAsBuffer(script);

  const isAnyoneCanPay = !!(sighash & anyoneCanPayFlag);
  const isNone = outputType === sigHashNone;
  const isSingle = outputType === sigHashSingle;

  // Without an output at the input's index, signing one output signs 1
  if (isSingle && !parts.outputs[vin]) {
    return {hash: oneHash};
  }

  // Other inputs only commit to their sequences when all outputs are signed
  const isSequenced = !isNone && !isSingle;

  parts.outpoints.forEach((outpoint, index) => {
    // The signing input commits to the script code
    if (index === vin) {
      const scriptLength = encode(scriptCode.length);

      inputs.push(outpoint, scriptLength, scriptCode, parts.sequences[vin]);

      return;
    }

    // Only the signing input is committed to when anyone can pay
    if (isAnyoneCanPay) {
      return;
    }

    const sequence = isSequenced ? parts.sequences[index] : zeroSequence;

    // Other inputs have an empty script
    inputs.push(outpoint, emptyScript, sequence);

    return;
  });

  // Signing for no outputs commits to none, for one output up to that output
  let committed = parts.outputs.length;

  if (isNone) {
    committed = noOutputs;
  } else if (isSingle) {
    committed = vin + 1;
  }

  const outputs = parts.outputs.slice(0, committed).map((output, index) => {
    // Outputs before the matching output are blanked
    return isSingle && index < vin ? blankOutput : output;
  });

  const preimage = Buffer.concat([
    parts.version,
    encode(isAnyoneCanPay ? singleInput : parts.outpoints.length),
    ...inputs,
    encode(outputs.length),
    ...outputs,
    parts.locktime,
    uint32AsBuffer({number: sighash}),
  ]);

  return {hash: hash256({data: preimage})};
};
