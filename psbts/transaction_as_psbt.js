const createPsbt = require('./create_psbt');
const {isMultisig} = require('./../script');
const {multisigDetails} = require('./../script');
const {script} = require('./../tokens');
const {Transaction} = require('./../tokens');
const updatePsbt = require('./update_psbt');

const bufferAsHex = buffer => buffer.toString('hex');
const {decompile} = script;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const isBech32Version = version => version !== undefined && version <= 16;
const {isBuffer} = Buffer;
const payToWitnessKeyOutLength = 20;
const reversedBuffer = buffer => Buffer.from(buffer).reverse();
const {SIGHASH_ALL} = Transaction;
const transactionId = hex => Transaction.fromHex(hex).getId();

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
  const tx = Transaction.fromHex(transaction);
  const witnessScripts = [];

  const {version} = tx;

  const outputs = tx.outs.map(({script, value}) => ({
    script: bufferAsHex(script),
    tokens: value,
  }));

  const utxos = tx.ins.map(({hash, index, sequence}) => ({
    sequence,
    id: bufferAsHex(reversedBuffer(hash)),
    vout: index,
  }));

  const {psbt} = createPsbt({outputs, utxos, version, timelock: tx.locktime});

  tx.ins.forEach(({hash, index, script, witness}, vin) => {
    const spends = spending.find(hex => {
      return hexAsBuffer(transactionId(hex)).equals(reversedBuffer(hash));
    });

    const out = Transaction.fromHex(spends).outs[index].script

    const [version, push] = decompile(out);

    // Output is a native segwit pay to witness public key hash
    if (isBech32Version(version) && push.length === payToWitnessKeyOutLength) {
      const [signature, publicKey] = witness;

      const [hashType] = reversedBuffer(signature);

      return signatures.push({
        vin,
        hash_type: hashType,
        public_key: bufferAsHex(publicKey),
        signature: bufferAsHex(signature),
      });
    }

    const {multisig} = multisigDetails({script: bufferAsHex(script)});

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

    const [witnessScript] = (witness || []).slice().reverse();

    if (!!witness && !!script.length) {
      redeemScripts.push(bufferAsHex(script));
    }

    if (!!witnessScript) {
      witnessScripts.push(bufferAsHex(witnessScript));
    }

    // Native witness multisig
    if (!!witnessScript && isMultisig({script: bufferAsHex(witnessScript)})) {
      const [, ...witnessMulti] = decompile(witnessScript).slice().reverse();

      const [n, m] = witnessMulti.slice().reverse().filter(n => !isBuffer(n));

      if (n !== m) {
        throw new Error('WitnessThresholdMultisigNotSupported');
      }

      const publicKeys = witnessMulti.slice().reverse().filter(isBuffer);

      const [, ...witnessElements] = witness.slice().reverse()

      const witnessSignatures = witnessElements.filter(n => !!n.length);

      return witnessSignatures.reverse().forEach((signature, i) => {
        const [hashType] = reversedBuffer(signature);

        return signatures.push({
          vin,
          hash_type: hashType,
          public_key: publicKeys[i],
          signature: bufferAsHex(signature),
        });
      });
    }

    // Pay to witness public key nested
    if (!!witnessScript && !!script.length) {
      const [redeem] = decompile(script).reverse();

      const [ver, push] = decompile(redeem);

      if (isBech32Version(ver) && push.length === payToWitnessKeyOutLength) {
        const [signature, publicKey] = witness;

        const [hashType] = reversedBuffer(signature);

        // There is no witness script for a p2wpkh, just signature, pubkey
        witnessScripts.length = Number();

        return signatures.push({
          vin,
          hash_type: hashType,
          public_key: bufferAsHex(publicKey),
          signature: bufferAsHex(signature),
        });
      }
    }

    // The output script is a pay to public key hash
    const [signature, publicKey] = decompile(script);

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
