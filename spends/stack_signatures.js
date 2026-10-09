const hash160 = require('./hash160');
const {scriptTemplate} = require('./../script');

const bufferAsHex = buffer => buffer.toString('hex');
const {isBuffer} = Buffer;

/** Find the signatures in the stack elements that satisfy a script

  The script pays to a public key, to a public key hash, or to a multisig
  where every key signs

  {
    [is_witness]: <Stack Is a Witness Stack Bool>
    script: <Script Hex String>
    stack: [<Stack Element Buffer Object or Op Code Number>]
  }

  @throws
  <PartialKeySigningNotSupported Error>
  <UnexpectedDifferentSignaturesForRepeatedKey Error>
  <UnsupportedTransactionSpendType Error>
  <WitnessThresholdMultisigNotSupported Error>

  @returns
  {
    signatures: [{
      hash_type: <Signature Hash Type Number>
      public_key: <Public Key Hex String>
      signature: <Signature Hex String>
    }]
  }
*/
module.exports = ({is_witness, script, stack}) => {
  const signatures = new Map();
  const template = scriptTemplate({script});

  // A signature is for a public key, and it ends with its sighash type
  const addSignature = (publicKey, signature) => {
    if (!isBuffer(signature)) {
      throw new Error('UnsupportedTransactionSpendType');
    }

    const existing = signatures.get(bufferAsHex(publicKey));

    // A key that is used twice cannot keep two different signatures
    if (!!existing && existing.signature !== bufferAsHex(signature)) {
      throw new Error('UnexpectedDifferentSignaturesForRepeatedKey');
    }

    signatures.set(bufferAsHex(publicKey), {
      hash_type: signature.at(-1),
      public_key: bufferAsHex(publicKey),
      signature: bufferAsHex(signature),
    });

    return;
  };

  // A script paying to a public key is satisfied by a signature of the key
  if (!!template.key) {
    const [signature] = stack;

    addSignature(template.key, signature);

    return {signatures: [...signatures.values()]};
  }

  // A script paying to a public key hash takes a signature and a public key
  if (!!template.hash) {
    const [signature, publicKey] = stack;

    // The public key must be the key that the script pays to
    if (!isBuffer(publicKey)) {
      throw new Error('UnsupportedTransactionSpendType');
    }

    const keyHash = hash160({data: publicKey});

    if (!keyHash.equals(template.hash)) {
      throw new Error('UnsupportedTransactionSpendType');
    }

    addSignature(publicKey, signature);

    return {signatures: [...signatures.values()]};
  }

  // Exit early when the script does not pay to keys that signatures are for
  if (!template.keys) {
    throw new Error('UnsupportedTransactionSpendType');
  }

  const isThreshold = template.required !== template.keys.length;

  // Signatures are only known to be for keys when every key signs
  if (isThreshold && !!is_witness) {
    throw new Error('WitnessThresholdMultisigNotSupported');
  }

  if (isThreshold) {
    throw new Error('PartialKeySigningNotSupported');
  }

  // The first element is the extra element that CHECKMULTISIG takes
  const [, ...multisigSignatures] = stack;

  template.keys.forEach((key, i) => addSignature(key, multisigSignatures[i]));

  return {signatures: [...signatures.values()]};
};
