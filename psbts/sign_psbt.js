const {crypto} = require('./../tokens');
const decodePsbt = require('./decode_psbt');
const {encodeSignature} = require('./../signatures');
const {hexBase} = require('./constants');
const {networks} = require('./../tokens');
const {payments} = require('./../tokens');
const {script} = require('./../tokens');
const {Transaction} = require('./../tokens');
const updatePsbt = require('./update_psbt');

const {decompile} = script;
const defaultSighashType = Transaction.SIGHASH_ALL;
const {hash160} = crypto;
const {p2pkh} = payments;

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

    keys[key.publicKey.toString('hex')] = key;
    pkHashes[hash160(key.publicKey).toString('hex')] = key;

    return;
  });

  try {
    decoded = decodePsbt({ecp: args.ecp, psbt: args.psbt});
  } catch (err) {
    throw err;
  }

  const tx = Transaction.fromHex(decoded.unsigned_transaction);
  const signatures = [];

  decoded.inputs.forEach((input, vin) => {
    // Absent bip32 derivations to look for, look in scripts for keys
    if (!input.bip32_derivations) {
      const scripts = [input.redeem_script, input.witness_script];

      // When there are no scripts, look for a witness pay to public key hash
      if (!!input.witness_utxo && !scripts.filter(n => !!n).length) {
        const scriptPub = input.witness_utxo.script_pub;

        const [, pkHash] = decompile(Buffer.from(scriptPub, 'hex'));

        const keyForHash = pkHashes[pkHash.toString('hex')];

        [keyForHash].filter(n => !!n).forEach(signingKey => {
          const hashToSign = tx.hashForWitnessV0(
            vin,
            p2pkh({hash: pkHash}).output,
            input.witness_utxo.tokens,
            input.sighash_type || defaultSighashType
          );

          const sig = encodeSignature({
            flag: input.sighash_type || defaultSighashType,
            signature: signingKey.sign(hashToSign).toString('hex'),
          });

          return signatures.push({
            vin,
            hash_type: input.sighash_type || defaultSighashType,
            public_key: signingKey.publicKey.toString('hex'),
            signature: sig.toString('hex'),
          });
        });
      }

      // Go through the scripts that match keys and add signatures
      scripts.filter(n => !!n).map(n => Buffer.from(n, 'hex')).forEach(n => {
        const buffers = decompile(n).filter(Buffer.isBuffer);

        // Lookup data pushes in the key and key hash indexes
        const keysToSign = buffers.map(b => b.toString('hex')).map(k => {
          return keys[k] || pkHashes[k];
        });

        // For each found key, add a signature
        keysToSign.filter(n => !!n).forEach(signingKey => {
          let hashToSign;
          let sighashType = input.sighash_type;

          // Witness input spending a witness utxo
          if (!!input.witness_script && !!n.witness_utxo) {
            const script = Buffer.from(input.witness_script, 'hex');
            const tokens = input.witness_utxo.tokens;

            hashToSign = tx.hashForWitnessV0(vin, script, tokens, sighashType);
          } if (!!input.witness_script && !!input.redeem_script) {
            // Nested witness input
            const nonWitnessUtxo = Transaction.fromHex(input.non_witness_utxo);
            const redeemScript = Buffer.from(input.redeem_script, 'hex');
            const script = Buffer.from(input.witness_script, 'hex');

            const nestedScriptHash = hash160(redeemScript);

            const tx = Transaction.fromHex(decoded.unsigned_transaction);

            // Find the value for the sigHash in the non-witness utxo
            const {value} = nonWitnessUtxo.outs.find(n => {
              return decompile(n.script)
                .filter(Buffer.isBuffer)
                .find(n => n.equals(nestedScriptHash));
            });

            hashToSign = tx.hashForWitnessV0(vin, script, value, sighashType);
          } else if (!!input.witness_script && !!input.non_witness_utxo) {
            const txWithOutputs = Transaction.fromHex(input.non_witness_utxo);

            const vout = tx.ins[vin].index;

            const script = Buffer.from(input.witness_script, 'hex');
            const tokens = txWithOutputs.outs[vout].value;

            hashToSign = tx.hashForWitnessV0(vin, script, tokens, sighashType);
          } else {
            // Non-witness script
            const forkId = networks[args.network].fork_id;

            const forkMod = parseInt(forkId || 0, hexBase);
            const redeem = Buffer.from(input.redeem_script, 'hex');
            const sigHash = input.sighash_type;
            let tokens;
            const spendsTx = Transaction.fromHex(input.non_witness_utxo);

            if (!!input.witness_utxo) {
              tokens = input.witness_utxo.tokens;
            } else if (!!input.non_witness_utxo) {
              tokens = spendsTx.outs[tx.ins[vin].index].value;
            }

            sighashType = !forkMod ? sigHash : forkMod | sigHash;

            const fork = tx.hashForWitnessV0(vin, redeem, tokens, sighashType);
            const normal = tx.hashForSignature(vin, redeem, sighashType);

            hashToSign = !!forkMod ? fork : normal;
          }

          if (!hashToSign) {
            return;
          }

          const sig = encodeSignature({
            flag: sighashType,
            signature: signingKey.sign(hashToSign).toString('hex'),
          });

          return signatures.push({
            vin,
            hash_type: sighashType,
            public_key: signingKey.publicKey.toString('hex'),
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
        const script = Buffer.from(input.witness_script, 'hex');
        const tokens = input.witness_utxo.tokens;

        hashToSign = tx.hashForWitnessV0(vin, script, tokens, sighashType);
      }

      if (!!input.non_witness_utxo && !!input.redeem_script) {
        const redeemScript = Buffer.from(input.redeem_script, 'hex');

        hashToSign = tx.hashForSignature(vin, redeemScript, sighashType);
      }

      if (!hashToSign) {
        return;
      }

      const signature = encodeSignature({
        flag: sighashType,
        signature: signingKey.sign(hashToSign).toString('hex')
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
