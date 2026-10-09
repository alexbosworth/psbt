const hash160 = require('./hash160');
const {scriptTemplate} = require('./../script');

const bufferAsHex = buffer => buffer.toString('hex');
const emptyElement = Buffer.alloc(0);

/** Make the stack elements that satisfy a script with signatures

  The script pays to a public key, to a public key hash, or to a multisig of
  public keys. Only valid signatures of the keys that it pays to are used.

  {
    script: <Script Buffer Object>
    signatures: [{
      is_valid: <Signature Is Valid Bool>
      public_key: <Public Key Buffer Object>
      signature: <Signature Buffer Object>
    }]
  }

  @throws
  <ExpectedAdditionalSignatures Error>
  <ExpectedSignatureForPaidPublicKey Error>
  <ExpectedValidSignatureForPaidPublicKey Error>
  <UnsupportedScriptTypeToFinalize Error>

  @returns
  {
    stack: [<Stack Element Buffer Object>]
  }
*/
module.exports = ({script, signatures}) => {
  const signed = [];
  const signaturesByKey = new Map();
  const template = scriptTemplate({script: bufferAsHex(script)});

  // A script that pays to a public key takes a signature of that key
  if (!!template.key) {
    const keySignature = signatures.find(n => {
      return n.public_key.equals(template.key);
    });

    if (!keySignature) {
      throw new Error('ExpectedSignatureForPaidPublicKey');
    }

    if (!keySignature.is_valid) {
      throw new Error('ExpectedValidSignatureForPaidPublicKey');
    }

    return {stack: [keySignature.signature]};
  }

  // A script that pays to a public key hash takes a signature and its key
  if (!!template.hash) {
    const keySignature = signatures.find(n => {
      const keyHash = hash160({data: n.public_key});

      return keyHash.equals(template.hash);
    });

    if (!keySignature) {
      throw new Error('ExpectedSignatureForPaidPublicKey');
    }

    if (!keySignature.is_valid) {
      throw new Error('ExpectedValidSignatureForPaidPublicKey');
    }

    return {stack: [keySignature.signature, keySignature.public_key]};
  }

  // Exit early when the script is not a kind of script that can be satisfied
  if (!template.keys) {
    throw new Error('UnsupportedScriptTypeToFinalize');
  }

  // Only valid signatures can be used to satisfy the multisig
  signatures.forEach(n => {
    if (!n.is_valid) {
      return;
    }

    return signaturesByKey.set(bufferAsHex(n.public_key), n.signature);
  });

  // Signatures are used in the order of their keys, until there are enough
  template.keys.forEach(key => {
    const signature = signaturesByKey.get(bufferAsHex(key));

    if (!!signature && signed.length < template.required) {
      signed.push(signature);
    }

    return;
  });

  if (signed.length < template.required) {
    throw new Error('ExpectedAdditionalSignatures');
  }

  // The extra element that CHECKMULTISIG takes is an empty element
  return {stack: [emptyElement, ...signed]};
};
