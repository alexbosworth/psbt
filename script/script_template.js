const {OP_1} = require('bitcoin-ops');
const {OP_16} = require('bitcoin-ops');
const {OP_CHECKMULTISIG} = require('bitcoin-ops');
const {OP_CHECKSIG} = require('bitcoin-ops');
const {OP_DUP} = require('bitcoin-ops');
const {OP_EQUALVERIFY} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const asElements = script => scriptAsScriptElements({script}).elements || [];
const countIndex = -2;
const firstKeyIndex = 1;
const {isBuffer} = Buffer;
const isSmallNumber = n => n >= OP_1 && n <= OP_16;
const numberOf = opCode => opCode - OP_1 + 1;
const p2pkElementsCount = 2;
const p2pkhElementsCount = 5;
const publicKeyHashByteLength = 20;

/** Get the public keys that a script checks signatures with

  Scripts that pay to a public key, to a public key hash, or to a multisig of
  public keys are supported. Other scripts have no keys.

  {
    script: <Script Hex String>
  }

  @returns
  {
    [hash]: <Paid Public Key Hash Buffer Object>
    [key]: <Paid Public Key Buffer Object>
    [keys]: [<Multisig Public Key Buffer Object>]
    [required]: <Multisig Required Signatures Count Number>
  }
*/
module.exports = ({script}) => {
  const elements = asElements(script);

  const [first, second, third, fourth, fifth] = elements;

  // A script that pays to a public key checks a signature with the key
  if (elements.length === p2pkElementsCount && second === OP_CHECKSIG) {
    return isBuffer(first) ? {key: first} : {};
  }

  const isHashCheck = first === OP_DUP && second === OP_HASH160;
  const isSigCheck = fourth === OP_EQUALVERIFY && fifth === OP_CHECKSIG;

  // A script that pays to a public key hash checks a key and its signature
  if (elements.length === p2pkhElementsCount && isHashCheck && isSigCheck) {
    const isHash = isBuffer(third) && third.length === publicKeyHashByteLength;

    return isHash ? {hash: third} : {};
  }

  // A multisig script checks signatures with the keys between its counts
  if (elements.at(-1) !== OP_CHECKMULTISIG) {
    return {};
  }

  const count = elements.at(countIndex);
  const keys = elements.slice(firstKeyIndex, countIndex);

  // The signatures required and the count of keys are numbers from 1 to 16
  if (!isSmallNumber(first) || !isSmallNumber(count)) {
    return {};
  }

  // Every element between the two numbers is a public key
  if (keys.filter(isBuffer).length !== keys.length) {
    return {};
  }

  if (keys.length !== numberOf(count)) {
    return {};
  }

  // A multisig cannot require more signatures than it has keys
  if (numberOf(first) > keys.length) {
    return {};
  }

  return {keys, required: numberOf(first)};
};
