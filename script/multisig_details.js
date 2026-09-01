const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const isMultisig = require('./is_multisig');

const asElements = script => scriptAsScriptElements({script}).elements;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isBuffer} = Buffer;
const isNotBuffer = n => !isBuffer(n);
const reversedBuffer = buffer => Buffer.from(buffer).reverse();

/** Get multisig details from a scriptSig

  {
    script: <Script Hex String>
  }

  @returns
  {
    [multisig]: {
      redeem_script: <Redeem Script Hex String>
      signatures: [{
        hash_type: <Signature Hash Type Number>
        public_key: <Public Key Hex String>
        signature: <Signature Hex String>
      }]
    }
  }
*/
module.exports = ({script}) => {
  if (!script) {
    return {};
  }

  const [redeemScript, ...elements] = asElements(script).reverse();

  const signatures = elements.filter(isBuffer).map(bufferAsHex).reverse();

  if (!isBuffer(redeemScript)) {
    return {};
  }

  if (!isMultisig({script: bufferAsHex(redeemScript)})) {
    return {};
  }

  const count = asElements(bufferAsHex(redeemScript)).filter(isNotBuffer);
  const keys = asElements(bufferAsHex(redeemScript)).filter(isBuffer);

  const [required, total] = count;

  if (required !== total) {
    throw new Error('PartialKeySigningNotSupported');
  }

  const hashTypes = signatures.map(signature => {
    const [hashType] = reversedBuffer(hexAsBuffer(signature));

    return hashType;
  });

  const publicKeys = keys.map(bufferAsHex);

  return {
    multisig: {
      redeem_script: bufferAsHex(redeemScript),
      signatures: signatures.map((sig, i) => ({
        hash_type: hashTypes[i],
        public_key: publicKeys[i],
        signature: signatures[i],
      })),
    },
  };
};
