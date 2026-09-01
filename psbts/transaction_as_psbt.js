const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {idForTransaction} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const createPsbt = require('./create_psbt');
const {isMultisig} = require('./../script');
const {multisigDetails} = require('./../script');
const updatePsbt = require('./update_psbt');

const asElements = script => scriptAsScriptElements({script}).elements;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const isBech32Version = version => version !== undefined && version <= 16;
const {isBuffer} = Buffer;
const payToWitnessKeyOutLength = 20;
const reversedBuffer = buffer => Buffer.from(buffer).reverse();
const transactionId = hex => idForTransaction({transaction: hex}).id;
const txOuts = tx => componentsOfTransaction({transaction: tx}).outputs;

/** Convert a signed transaction to a signed PSBT

  Note: not all signed transactions can be converted to a signed PSBT. For
  example, a preimage cannot be represented in a standard PSBT.

  {
    ecp: <ECPair Object>
    spending: [<Spending Transaction Hex String>]
    transaction: <Hex Encoded Transaction String>
  }

  @throws
  <Error>

  @returns
  {
    psbt: <Signed PSBT String>
  }
*/
module.exports = ({ecp, spending, transaction}) => {
  const redeemScripts = [];
  const signatures = [];
  const tx = componentsOfTransaction({transaction});
  const witnessScripts = [];

  const {version} = tx;

  const outputs = tx.outputs;

  const utxos = tx.inputs.map(({id, sequence, vout}) => ({sequence, id, vout}));

  const {psbt} = createPsbt({outputs, utxos, version, timelock: tx.locktime});

  tx.inputs.forEach(({id, script, vout, witness = []}, vin) => {
    const spends = spending.find(hex => transactionId(hex) === id);

    const out = txOuts(spends)[vout].script;

    const [version, push] = asElements(out);

    // Output is a native segwit pay to witness public key hash
    if (isBech32Version(version) && push.length === payToWitnessKeyOutLength) {
      const [signature, publicKey] = witness;

      const [hashType] = reversedBuffer(hexAsBuffer(signature));

      return signatures.push({
        vin,
        signature,
        hash_type: hashType,
        public_key: publicKey,
      });
    }

    const {multisig} = multisigDetails({script});

    if (!!multisig) {
      multisig.signatures.forEach(signature => {
        return signatures.push({
          vin,
          hash_type: signature.hash_type,
          public_key: signature.public_key,
          signature: signature.signature,
        });
      });

      return redeemScripts.push(multisig.redeem_script);
    }

    const [witnessScript] = witness.slice().reverse();

    if (!!witness && !!script.length) {
      redeemScripts.push(script);
    }

    if (!!witnessScript) {
      witnessScripts.push(witnessScript);
    }

    // Native witness multisig
    if (!!witnessScript && isMultisig({script: witnessScript})) {
      const [, ...witnessMulti] = asElements(witnessScript).slice().reverse();

      const [n, m] = witnessMulti.slice().reverse().filter(n => !isBuffer(n));

      if (n !== m) {
        throw new Error('WitnessThresholdMultisigNotSupported');
      }

      const publicKeys = witnessMulti.slice().reverse().filter(isBuffer);

      const [, ...witnessElements] = witness.slice().reverse()

      const witnessSignatures = witnessElements.filter(n => !!n.length);

      return witnessSignatures.reverse().forEach((signature, i) => {
        const [hashType] = reversedBuffer(hexAsBuffer(signature));

        return signatures.push({
          vin,
          signature,
          hash_type: hashType,
          public_key: publicKeys[i],
        });
      });
    }

    // Pay to witness public key nested
    if (!!witnessScript && !!script.length) {
      const [redeem] = asElements(script).reverse();

      const [ver, push] = asElements(bufferAsHex(redeem));

      if (isBech32Version(ver) && push.length === payToWitnessKeyOutLength) {
        const [signature, publicKey] = witness;

        const [hashType] = reversedBuffer(hexAsBuffer(signature));

        // There is no witness script for a p2wpkh, just signature, pubkey
        witnessScripts.length = Number();

        return signatures.push({
          vin,
          signature,
          hash_type: hashType,
          public_key: publicKey,
        });
      }
    }

    // The output script is a pay to public key hash
    const [signature, publicKey] = asElements(script);

    if (!signature || !publicKey) {
      throw new Error('UnsupportedTransactionSpendType');
    }

    const [hashType] = reversedBuffer(signature);

    return signatures.push({
      vin,
      hash_type: hashType,
      public_key: bufferAsHex(publicKey),
      signature: bufferAsHex(signature),
    });
  });

  return updatePsbt({
    ecp,
    psbt,
    signatures,
    transactions: spending,
    redeem_scripts: redeemScripts,
    witness_scripts: witnessScripts,
  });
};
