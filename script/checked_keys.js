const {OP_1} = require('bitcoin-ops');
const {OP_16} = require('bitcoin-ops');
const {OP_CHECKMULTISIG} = require('bitcoin-ops');
const {OP_CHECKMULTISIGVERIFY} = require('bitcoin-ops');
const {OP_CHECKSIG} = require('bitcoin-ops');
const {OP_CHECKSIGVERIFY} = require('bitcoin-ops');
const {OP_DUP} = require('bitcoin-ops');
const {OP_EQUALVERIFY} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const asElements = script => scriptAsScriptElements({script}).elements || [];
const hashByteLength = 20;
const {isBuffer} = Buffer;
const isSmallNumber = n => n >= OP_1 && n <= OP_16;
const multiSigChecks = [OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY];
const numberOf = opCode => opCode - OP_1 + 1;
const sigChecks = [OP_CHECKSIG, OP_CHECKSIGVERIFY];

/** Get the public keys and public key hashes that a script checks signatures
  with

  A key pushed right before a signature check is the key that it checks, as
  are the keys of a multisig check and the key of a key hash check. A key
  that a script only has as data is not checked.

  {
    script: <Script Hex String>
  }

  @returns
  {
    hashes: [<Checked Public Key Hash Buffer Object>]
    keys: [<Checked Public Key Buffer Object>]
  }
*/
module.exports = ({script}) => {
  const elements = asElements(script);
  const hashes = [];
  const keys = [];

  elements.forEach((element, i) => {
    // A signature check checks the key that is pushed right before it
    if (sigChecks.includes(element)) {
      const key = elements[i - 1];

      if (isBuffer(key)) {
        keys.push(key);
      }

      const hash = elements[i - 2];
      const isDup = elements[i - 4] === OP_DUP;
      const isHash160 = elements[i - 3] === OP_HASH160;
      const isVerified = elements[i - 1] === OP_EQUALVERIFY;

      const isHash = isBuffer(hash) && hash.length === hashByteLength;

      // A key hash check checks the key that hashes to the pushed hash
      if (isDup && isHash160 && isHash && isVerified) {
        hashes.push(hash);
      }

      return;
    }

    // Exit early when the element is not a multisig check
    if (!multiSigChecks.includes(element)) {
      return;
    }

    const count = elements[i - 1];

    if (!isSmallNumber(count)) {
      return;
    }

    // The keys of a multisig check are between its two numbers
    const start = i - 1 - numberOf(count);

    const required = elements[start - 1];

    if (start < 1 || !isSmallNumber(required)) {
      return;
    }

    const checked = elements.slice(start, i - 1);

    // Every element between the two numbers is a key that is checked
    if (checked.filter(isBuffer).length !== checked.length) {
      return;
    }

    // A multisig cannot require more signatures than it has keys
    if (numberOf(required) > checked.length) {
      return;
    }

    checked.forEach(key => keys.push(key));

    return;
  });

  return {hashes, keys};
};
