const {createHash} = require('node:crypto');

const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {nonWitnessHashToSign} = require('@alexbosworth/blockchain');
const {p2pkhOutputScript} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');
const {v0HashToSign} = require('@alexbosworth/blockchain');

const decodePsbt = require('./decode_psbt');
const {encodeSignature} = require('./../signatures');
const networks = require('./networks');
const updatePsbt = require('./update_psbt');

const asBuffer = n => Buffer.from(n);
const asElements = script => scriptAsScriptElements({script}).elements;
const bufferAsHex = buffer => buffer.toString('hex');
const defaultSighashType = 0x01;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const hash160 = n => createHash('ripemd160').update(sha256(n)).digest();
const sha256 = n => createHash('sha256').update(n).digest();

/** Update a PSBT with signatures

  {
    ecp: <ECPair Object>
    network: <Network Name String>
    psbt: <BIP 174 Encoded PSBT Hex String>
    signing_keys: [<WIF Encoded Private Key String>]
  }

  @throws
  <Sign PSBT Error>

  @returns
  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }
*/
module.exports = args => {
  let decoded;
  const keys = {};
  const network = networks[args.network];
  const pkHashes = {};

  args.signing_keys.map(k => {
    const key = args.ecp.fromWIF(k, network);

    keys[asBuffer(key.publicKey).toString('hex')] = key;
    pkHashes[hash160(asBuffer(key.publicKey)).toString('hex')] = key;

    return;
  });

  try {
    decoded = decodePsbt({ecp: args.ecp, psbt: args.psbt});
  } catch (err) {
    throw err;
  }

  const signatures = [];

  decoded.inputs.forEach((input, vin) => {
    // Absent bip32 derivations to look for, look in scripts for keys
    if (!input.bip32_derivations) {
      const scripts = [input.redeem_script, input.witness_script];

      // When there are no scripts, look for a witness pay to public key hash
      if (!!input.witness_utxo && !scripts.filter(n => !!n).length) {
        const scriptPub = input.witness_utxo.script_pub;

        const [, pkHash] = asElements(scriptPub);

        const keyForHash = pkHashes[pkHash.toString('hex')];

        [keyForHash].filter(n => !!n).forEach(signingKey => {
          const {hash} = v0HashToSign({
            vin,
            script: bufferAsHex(p2pkhOutputScript({hash: pkHash}).script),
            sighash: input.sighash_type || defaultSighashType,
            tokens: input.witness_utxo.tokens,
            transaction: decoded.unsigned_transaction,
          });

          const hashToSign = hexAsBuffer(hash);

          const sig = encodeSignature({
            flag: input.sighash_type || defaultSighashType,
            signature: asBuffer(signingKey.sign(hashToSign)).toString('hex'),
          });

          return signatures.push({
            vin,
            hash_type: input.sighash_type || defaultSighashType,
            public_key: asBuffer(signingKey.publicKey).toString('hex'),
            signature: sig.toString('hex'),
          });
        });
      }

      // Go through the scripts that match keys and add signatures
      scripts.filter(n => !!n).forEach(n => {
        const buffers = asElements(n).filter(Buffer.isBuffer);

        // Lookup data pushes in the key and key hash indexes
        const keysToSign = buffers.map(b => b.toString('hex')).map(k => {
          return keys[k] || pkHashes[k];
        });

        // For each found key, add a signature
        keysToSign.filter(n => !!n).forEach(signingKey => {
          let hashToSign;
          const sighashType = input.sighash_type;

          // Witness input spending a witness utxo
          if (!!input.witness_script && !!input.witness_utxo) {
            const {hash} = v0HashToSign({
              vin,
              script: input.witness_script,
              sighash: sighashType,
              tokens: input.witness_utxo.tokens,
              transaction: decoded.unsigned_transaction,
            });

            hashToSign = hexAsBuffer(hash);
          } else if (!!input.witness_script && !!input.redeem_script) {
            // Nested witness input
            const nonWitnessUtxo = componentsOfTransaction({
              transaction: input.non_witness_utxo,
            });
            const redeemScript = Buffer.from(input.redeem_script, 'hex');

            const nestedScriptHash = hash160(redeemScript);

            // Find the value for the sigHash in the non-witness utxo
            const {tokens} = nonWitnessUtxo.outputs.find(n => {
              return asElements(n.script)
                .filter(Buffer.isBuffer)
                .find(n => n.equals(nestedScriptHash));
            });

            const {hash} = v0HashToSign({
              vin,
              tokens,
              script: input.witness_script,
              sighash: sighashType,
              transaction: decoded.unsigned_transaction,
            });

            hashToSign = hexAsBuffer(hash);
          } else if (!!input.witness_script && !!input.non_witness_utxo) {
            const txWithOutputs = componentsOfTransaction({
              transaction: input.non_witness_utxo,
            });

            const tx = componentsOfTransaction({
              transaction: decoded.unsigned_transaction,
            });

            const {vout} = tx.inputs[vin];

            const {hash} = v0HashToSign({
              vin,
              script: input.witness_script,
              sighash: sighashType,
              tokens: txWithOutputs.outputs[vout].tokens,
              transaction: decoded.unsigned_transaction,
            });

            hashToSign = hexAsBuffer(hash);
          } else {
            // Non-witness script
            const {hash} = nonWitnessHashToSign({
              vin,
              script: input.redeem_script,
              sighash: sighashType,
              transaction: decoded.unsigned_transaction,
            });

            hashToSign = hexAsBuffer(hash);
          }

          const sig = encodeSignature({
            flag: sighashType,
            signature: asBuffer(signingKey.sign(hashToSign)).toString('hex'),
          });

          return signatures.push({
            vin,
            hash_type: sighashType,
            public_key: asBuffer(signingKey.publicKey).toString('hex'),
            signature: sig.toString('hex'),
          });
        });
      });
    }

    // Given BIP32 derivations, attach relevant signatures for each
    (input.bip32_derivations || []).forEach(bip32 => {
      const signingKey = keys[bip32.public_key];

      if (!signingKey) {
        return;
      }

      let hashToSign;
      const sighashType = input.sighash_type;

      if (!!input.witness_script && !!input.witness_utxo) {
        const {hash} = v0HashToSign({
          vin,
          script: input.witness_script,
          sighash: sighashType,
          tokens: input.witness_utxo.tokens,
          transaction: decoded.unsigned_transaction,
        });

        hashToSign = hexAsBuffer(hash);
      }

      if (!!input.non_witness_utxo && !!input.redeem_script) {
        const {hash} = nonWitnessHashToSign({
          vin,
          script: input.redeem_script,
          sighash: sighashType,
          transaction: decoded.unsigned_transaction,
        });

        hashToSign = hexAsBuffer(hash);
      }

      if (!hashToSign) {
        return;
      }

      const signature = encodeSignature({
        flag: sighashType,
        signature: asBuffer(signingKey.sign(hashToSign)).toString('hex'),
      });

      return signatures.push({
        vin,
        hash_type: sighashType,
        public_key: bip32.public_key,
        signature: signature.toString('hex'),
      });
    });
  });

  return updatePsbt({signatures, ecp: args.ecp, psbt: args.psbt});
};
