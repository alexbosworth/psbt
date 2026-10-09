const {p2pkhOutputScript} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const {isP2shScript} = require('./../utxos');
const {isWitnessProgram} = require('./../utxos');
const {p2pkhHashByteLength} = require('./../utxos/constants');
const {p2wshHashByteLength} = require('./../utxos/constants');
const stackSignatures = require('./stack_signatures');
const {witnessProgram} = require('./../utxos');

const asElements = script => scriptAsScriptElements({script}).elements || [];
const bufferAsHex = buffer => buffer.toString('hex');
const elementsBeforeScript = elements => elements.slice(0, -1);
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isBuffer} = Buffer;
const versionZero = 0;

/** Find the signatures and scripts of a signed input from the output it spends

  {
    script: <Input ScriptSig Hex String>
    spent: <Spent Output Script Hex String>
    witness: [<Witness Stack Element Hex String>]
  }

  @throws
  <Error>

  @returns
  {
    [redeem_script]: <Redeem Script Hex String>
    signatures: [{
      hash_type: <Signature Hash Type Number>
      public_key: <Public Key Hex String>
      signature: <Signature Hex String>
    }]
    [witness_script]: <Witness Script Hex String>
  }
*/
module.exports = ({script, spent, witness}) => {
  const elements = asElements(script);
  const output = hexAsBuffer(spent);
  const stack = witness.map(hexAsBuffer);

  const isP2sh = isP2shScript({script: output});

  // A P2SH spend pushes the redeem script last, and it is kept with the input
  const redeem = isP2sh ? elements.at(-1) : undefined;

  if (isP2sh && !isBuffer(redeem)) {
    throw new Error('ExpectedRedeemScriptForScriptHashSpend');
  }

  // A legacy P2SH spend has the elements that satisfy its redeem script first
  if (isP2sh && !isWitnessProgram({script: redeem})) {
    const {signatures} = stackSignatures({
      script: bufferAsHex(redeem),
      stack: elementsBeforeScript(elements),
    });

    return {signatures, redeem_script: bufferAsHex(redeem)};
  }

  // A witness program is the output script or the redeem script nesting it
  const {program, version} = witnessProgram({
    script: isP2sh ? redeem : output,
  });

  // Exit early when a legacy output is satisfied by the scriptSig elements
  if (!program) {
    const {signatures} = stackSignatures({script: spent, stack: elements});

    return {signatures};
  }

  const redeemScript = isP2sh ? bufferAsHex(redeem) : undefined;

  // Only version 0 witness spends carry signatures for public keys
  if (version !== versionZero) {
    throw new Error('UnsupportedTransactionSpendType');
  }

  // A public key hash program is satisfied like a P2PKH script of the hash
  if (program.length === p2pkhHashByteLength) {
    const {script: keyHashScript} = p2pkhOutputScript({hash: program});

    const {signatures} = stackSignatures({
      stack,
      is_witness: true,
      script: bufferAsHex(keyHashScript),
    });

    return {signatures, redeem_script: redeemScript};
  }

  // A script hash program is spent with its witness script as the last element
  if (program.length !== p2wshHashByteLength || !stack.length) {
    throw new Error('UnsupportedTransactionSpendType');
  }

  const witnessScript = bufferAsHex(stack.at(-1));

  const {signatures} = stackSignatures({
    is_witness: true,
    script: witnessScript,
    stack: elementsBeforeScript(stack),
  });

  return {
    signatures,
    redeem_script: redeemScript,
    witness_script: witnessScript,
  };
};
