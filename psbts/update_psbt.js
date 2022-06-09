const BN = require('bn.js');
const {encode} = require('varuint-bitcoin');
const {OP_0} = require('bitcoin-ops');
const {OP_EQUAL} = require('bitcoin-ops');
const {OP_HASH160} = require('bitcoin-ops');

const {bip32Path} = require('./../bip32');
const {crypto} = require('./../tokens');
const {decBase} = require('./constants');
const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
const {encodeSignature} = require('./../signatures');
const {endianness} = require('./constants');
const {isMultisig} = require('./../script');
const {opNumberOffset} = require('./constants');
const {pushData} = require('./../script');
const {script} = require('./../tokens');
const {sigHashByteLength} = require('./constants');
const {stackIndexByteLength} = require('./constants');
const {tokensByteLength} = require('./constants');
const {Transaction} = require('./../tokens');
const types = require('./types');

const {decompile} = script;
const {hash160} = crypto;
const {isBuffer} = Buffer;
const isNestedP2wpkhReedeemScript = n => !!n && n.length === 44;
const publicKeyHashLength = 20;
const redeemHashLength = 20;
const {sha256} = crypto;
const transactionId = tx => Transaction.fromHex(tx).getId();
const txOuts = tx => Transaction.fromHex(tx).outs;

/** Update a PSBT

  {
    [additional_attributes]: [{
      type: <Type Hex String>
      value: <Value Hex String>
      vin: <Input Index Number>
      vout: <Output Index Number>
    }]
    [bip32_derivations]: [{
      fingerprint: <BIP 32 Fingerprint of Parent's Key Hex String>
      path: <BIP 32 Derivation Path String>
      public_key: <Public Key String>
    }]
    ecp: <ECPair Object>
    psbt: <BIP 174 Encoded PSBT String>
    [redeem_scripts]: [<Hex Encoded Redeem Script String>]
    [sighashes]: [{
      id: <Transaction Id String>
      sighash: <Sighash Flag Number>
      vout: <Spending Output Index Number>
    }]
    [signatures]: [{
      hash_type: <Signature Hash Type Number>
      public_key: <BIP 32 Public Key String>
      signature: <Signature Hex String>
      vin: <Signature Input Index Number>
    }]
    [taproot_inputs]: [{
      [key_spend_sig]: <Taproot Key Spend Signature Hex String>
      vin: <Input Index Number>
    }]
    [transactions]: [<Hex Encoding Transaction String>]
    [witness_scripts]: [<Witness Script String>]
  }

  @throws
  <Update PSBT Error>

  @returns
  {
    psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
  }
*/
module.exports = args => {
  if (!args.ecp) {
    throw new Error('ExpectedEcpairObjectToUpdatePsbt');
  }

  if (!args.psbt) {
    throw new Error('ExpectedPsbtToUpdate');
  }

  const addAttributes = args.additional_attributes || [];
  const bip32Derivations = args.bip32_derivations || [];
  const decoded = decodePsbt({ecp: args.ecp, psbt: args.psbt});
  const inputs = [];
  const outputs = [];
  const pairs = [];
  const pubKeyHashes = {};
  const pubKeys = {};
  const redeemScripts = args.redeem_scripts || [];
  const redeems = {};
  const scriptPubs = {};
  const sighashes = {};
  const signatures = {};
  const transactions = args.transactions || [];
  const txs = {};
  const witnessScripts = args.witness_scripts || [];
  const witnesses = {};

  const tx = Transaction.fromHex(decoded.unsigned_transaction);

  decoded.inputs = decoded.inputs.map(input => {
    return !Object.keys(input).length ? null : input;
  });

  // The unsigned transaction is the top pair
  pairs.push({
    type: Buffer.from(types.global.unsigned_tx, 'hex'),
    value: tx.toBuffer(),
  });

  addAttributes.forEach(({type, value, vin, vout}) => {
    if (vin !== undefined || vout !== undefined) {
      return;
    }

    return pairs.push({
      type: Buffer.from(type, 'hex'),
      value: Buffer.from(value, 'hex'),
    });
  });

  pairs.push({separator: true});

  // Index public keys and public key hashes for lookup
  bip32Derivations.forEach(n => {
    const pkHash = hash160(Buffer.from(n.public_key, 'hex')).toString('hex');

    pubKeyHashes[pkHash] = n;
    pubKeys[n.public_key] = n;

    return;
  });

  // Index sighashes by spending outpoint
  if (Array.isArray(args.sighashes)) {
    args.sighashes.forEach(n => sighashes[`${n.id}:${n.vout}`] = n.sighash);
  }

  // Index signatures by vin
  if (Array.isArray(args.signatures)) {
    args.signatures.forEach(n => signatures[n.vin] = signatures[n.vin] || []);
    args.signatures.forEach(n => signatures[n.vin].push(n));
  }

  // Index transactions by id
  transactions.forEach(t => txs[Transaction.fromHex(t).getId()] = t);

  // Index redeem scripts by redeem script hash
  redeemScripts.map(n => Buffer.from(n, 'hex')).forEach(script => {
    const scriptBuffers = decompile(script).filter(Buffer.isBuffer);

    scriptBuffers
      .map(n => n.toString('hex'))
      .forEach(n => redeems[n] = script);

    const foundKeys = scriptBuffers.map(n => pubKeys[n.toString('hex')]);

    return redeems[hash160(script).toString('hex')] = {
      script,
      bip32_derivations: foundKeys.filter(n => !!n),
    };
  });

  // Index witness scripts by the witness script hash, nested script hash
  witnessScripts.map(n => Buffer.from(n, 'hex')).forEach(script => {
    const witnessHash = sha256(script).toString('hex');

    witnesses[witnessHash] = {witness: script};

    const redeemScript = redeems[witnessHash];

    // Exit early when there is no nested p2sh
    if (!redeemScript) {
      return;
    }

    const decompiledBuffers = decompile(script).filter(Buffer.isBuffer);

    const foundKeys = decompiledBuffers.map(n => pubKeys[n.toString('hex')]);

    // Index using the nested scriptPub hash
    witnesses[hash160(redeemScript).toString('hex')] = {
      derivations: foundKeys.filter(n => !!n),
      redeem: redeemScript,
      witness: script,
    };

    return;
  });

  // Iterate through transaction inputs and fill in values
  tx.ins.forEach((input, vin) => {
    const utxo = decoded.inputs[vin] || {};

    const spendsTxId = input.hash.reverse().toString('hex');

    utxo.sighash_type = sighashes[`${spendsTxId}:${input.index}`];

    if (Array.isArray(signatures[vin])) {
      utxo.partial_sig = signatures[vin];
      signatures[vin].forEach(n => utxo.sighash_type = n.hash_type);
    }

    const spends = txs[spendsTxId];

    if (!spends) {
      return inputs.push(null);
    }

    const spendsTx = Transaction.fromHex(spends);

    // Find the non-witness output
    const out = spendsTx.outs
      .filter(({script}) => {
        const [, hash] = decompile(script);

        return Buffer.isBuffer(hash);
      })
      .map(({script}) => {
        const [, hash] = decompile(script);

        const index = hash.toString('hex');

        const redeem = redeems[index] || {};

        return {
          index,
          derivations: redeem.bip32_derivations,
          redeem: redeem.script,
        };
      })
      .find(({index}) => !!redeems[index]);

    // Find the output in the spending transaction that matches the input
    const outW = spendsTx.outs
      .filter(({script}) => {
        const [, scriptHash] = decompile(script);

        return Buffer.isBuffer(scriptHash);
      })
      .map(({script, value}) => {
        // Get the hash being spent, either a P2SH or a P2WSH
        const [, scriptHash] = decompile(script);

        const hash = scriptHash.toString('hex');

        const matchingWitness = witnesses[hash] || {};

        const {derivations, redeem, witness} = matchingWitness;

        return {derivations, hash, redeem, script, value, witness};
      })
      .find(({hash}) => !!witnesses[hash]);

    const spending = args.transactions.find(transaction => {
      return transactionId(transaction) === input.hash.toString('hex');
    });

    const spendOut = !spending ? null : txOuts(spending)[input.index];

    if (!!outW && !!outW.witness) {
      utxo.witness_script = outW.witness.toString('hex');
    }

    if (!!spendOut) {
      const [, spendScript] = decompile(spendOut.script);

      // Look for a redeem script that matches this spend out script
      const redeemScript = (args.redeem_scripts || []).find(script => {
        // Exit early when there is no spend script
        if (!Buffer.isBuffer(spendScript)) {
          return false;
        }

        const [push] = decompile(Buffer.from(script, 'hex'));

        if (!Buffer.isBuffer(push)) {
          return false;
        }

        return spendScript.equals(hash160(push));
      });

      if (!!redeemScript) {
        const [redeem] = decompile(Buffer.from(redeemScript, 'hex'));

        utxo.redeem_script = redeem.toString('hex');

        const [push] = decompile(Buffer.from(redeemScript, 'hex'));

        if (!!push) {
          const [, hash] = decompile(push);

          if (!!hash && !!witnesses[hash.toString('hex')]) {
            const {witness} = witnesses[hash.toString('hex')];

            utxo.witness_script = witness.toString('hex');
          }
        }
      }
    }

    const nestedP2wpkh = (() => {
      try {
        const [opHash160, hash, opEqual] = decompile(spendOut.script);

        const isP2shPush = isBuffer(hash) && hash.length === redeemHashLength;

        if (opHash160 !== OP_HASH160 || opEqual !== OP_EQUAL && !isP2shPush) {
          return false;
        }

        return args.redeem_scripts.find(redeem => {
          const [pushedScript] = decompile(Buffer.from(redeem, 'hex'));

          return hash160(pushedScript).equals(hash);
        });
      } catch (err) {
        return false;
      }
    })();

    const isP2wkh = (() => {
      const decompiled = decompile(spendOut.script);

      if (decompiled.length !== 2) {
        return false;
      }

      const [version, push] = decompiled;

      return push.length === publicKeyHashLength;
    })();

    if (!!spendsTx.hasWitnesses() || isP2wkh || !!nestedP2wpkh) {
      // utxo.non_witness_utxo = spends.toString('hex');
      utxo.witness_utxo = {
        script_pub: spendOut.script.toString('hex'),
        tokens: spendOut.value,
      };
    } else {
      utxo.non_witness_utxo = spends.toString('hex');
    }

    const legacyOutputBip32 = (out || {}).derivations || [];
    const redeemScript = (out || outW || {}).redeem;
    const witnessOutputBip32 = (outW || {}).derivations || [];

    const outBip32 = legacyOutputBip32.concat(witnessOutputBip32);

    utxo.bip32_derivations = outBip32.filter(n => !!n);

    if (!!redeemScript) {
      utxo.redeem_script = redeemScript.toString('hex');
    }

    if (isP2wkh) {
      const [, hash] = decompile(spendOut.script);

      const derivation = pubKeyHashes[hash.toString('hex')];

      if (derivation) {
        utxo.bip32_derivations = [derivation];
      }
    }

    return inputs.push(utxo);
  });

  // Encode inputs into key value pairs
  tx.ins.forEach((txIn, vin) => {
    const n = inputs[vin] || decoded.inputs[vin];

    // Look for a taproot input
    const taprootInput = (args.taproot_inputs || []).find(n => n.vin === vin);

    // Legacy UTXO being spent by this input
    if (!!n.non_witness_utxo) {
      pairs.push({
        type: Buffer.from(types.input.non_witness_utxo, 'hex'),
        value: Buffer.from(n.non_witness_utxo, 'hex'),
      });
    }

    // Witness UTXO being spent by this input
    if (!!n.witness_utxo) {
      const script = Buffer.from(n.witness_utxo.script_pub, 'hex');

      const tokens = new BN(n.witness_utxo.tokens, decBase)
        .toArrayLike(Buffer, endianness, tokensByteLength);

      pairs.push({
        type: Buffer.from(types.input.witness_utxo, 'hex'),
        value: Buffer.concat([tokens, encode(script.length), script]),
      });
    }

    // Partial signature
    if (!args.is_final && !!n.partial_sig) {
      n.partial_sig.forEach(n => {
        return pairs.push({
          type: Buffer.concat([
            Buffer.from(types.input.partial_sig, 'hex'),
            Buffer.from(n.public_key, 'hex'),
          ]),
          value: Buffer.from(n.signature, 'hex'),
        });
      });
    }

    // Pay to Taproot partial signature for key spend
    if (!args.is_final && !!taprootInput && taprootInput.key_spend_sig) {
      pairs.push({
        type: Buffer.from(types.input.tap_key_sig, 'hex'),
        value: Buffer.from(taprootInput.key_spend_sig, 'hex'),
      });
    }

    // Sighash used to sign this input
    if (!args.is_final && !!n.sighash_type) {
      const sighash = new BN(n.sighash_type, decBase);

      pairs.push({
        type: Buffer.from(types.input.sighash_type, 'hex'),
        value: sighash.toArrayLike(Buffer, endianness, sigHashByteLength),
      });
    }

    // Redeem script used in the scriptsig of this input
    if (!args.is_final && !!n.redeem_script) {
      pairs.push({
        type: Buffer.from(types.input.redeem_script, 'hex'),
        value: Buffer.from(n.redeem_script, 'hex'),
      });
    }

    // Witness script used in this input
    if (!args.is_final && !!n.witness_script) {
      pairs.push({
        type: Buffer.from(types.input.witness_script, 'hex'),
        value: Buffer.from(n.witness_script, 'hex'),
      });
    }

    // Bip 32 derivations for this input
    if (!args.is_final && !!n.bip32_derivations) {
      // Sort in-place the derivations by pubkey ascending
      n.bip32_derivations.sort((a, b) => a.public_key < b.public_key ? -1 : 1);

      n.bip32_derivations.forEach(n => {
        pairs.push({
          type: Buffer.concat([
            Buffer.from(types.input.bip32_derivation, 'hex'),
            Buffer.from(n.public_key, 'hex'),
          ]),
          value: Buffer.concat([
            Buffer.from(n.fingerprint, 'hex'),
            bip32Path({path: n.path}),
          ]),
        });
      });
    }

    const hasPartialSig = !!n.partial_sig && !!n.partial_sig.length;
    const hasTaprootSig = !!n.taproot_key_spend_sig;

    // Make sure that there is a signature when the input is finalized
    if (!!args.is_final && !hasPartialSig && !hasTaprootSig) {
      throw new Error('ExpectedSignaturesForFinalizedTransaction');
    }

    // Final scriptwitness for taproot input
    if (!!args.is_final && !!n.taproot_key_spend_sig) {
      const components = [pushData({
        data: Buffer.from(n.taproot_key_spend_sig, 'hex'),
      })];

      const value = Buffer.concat([
        encode(components.length),
        Buffer.concat(components),
      ]);

      pairs.push({
        value,
        type: Buffer.from(types.input.final_scriptwitness, 'hex'),
      });
    }

    // Final scriptsig for this input
    if (!!args.is_final && !!n.partial_sig && !!n.partial_sig.length) {
      const isWitness = !!n.witness_script && !n.witness_utxo;
      const redeem = n.redeem_script;
      const [signature] = n.partial_sig;

      const isP2shMultisig = !!redeem && isMultisig({script: redeem});

      const sigs = n.partial_sig.map(n => {
        const sig = encodeSignature({
          flag: n.hash_type,
          signature: n.signature,
        });

        return Buffer.concat([encode(sig.length), sig]);
      });

      // Pay to Public Key?
      if (!n.redeem_script && !n.witness_script && !n.witness_utxo) {
        n.partial_sig.forEach(partial => {
          const pubKey = Buffer.from(partial.public_key, 'hex');

          const sig = encodeSignature({
            flag: partial.hash_type,
            signature: partial.signature,
          });

          const sigPush = Buffer.concat([encode(sig.length), sig]);
          const pubKeyPush = Buffer.concat([encode(pubKey.length), pubKey]);

          pairs.push({
            type: Buffer.from(types.input.final_scriptsig, 'hex'),
            value: Buffer.concat([sigPush, pubKeyPush]),
          });
        });
      }

      // Pay to witness public key hash
      if (!n.redeem_script && !n.witness_script && !!n.witness_utxo) {
        n.partial_sig.forEach(partial => {
          const sig = encodeSignature({
            flag: partial.hash_type,
            signature: partial.signature,
          });

          const components = []
            .concat(pushData({data: sig}))
            .concat(pushData({data: Buffer.from(partial.public_key, 'hex')}));

          const value = Buffer.concat([
            encode(components.length),
            Buffer.concat(components),
          ]);

          pairs.push({
            value,
            type: Buffer.from(types.input.final_scriptwitness, 'hex'),
          });
        });
      }

      if (isNestedP2wpkhReedeemScript(n.redeem_script) && !!n.witness_utxo) {
        n.partial_sig.forEach(partial => {
          const sig = encodeSignature({
            flag: partial.hash_type,
            signature: partial.signature,
          });

          const components = []
            .concat(pushData({data: sig}))
            .concat(pushData({data: Buffer.from(partial.public_key, 'hex')}));

          const value = Buffer.concat([
            encode(components.length),
            Buffer.concat(components),
          ]);

          const redeemScript = Buffer.from(n.redeem_script, 'hex');

          pairs.push({
            value: pushData({data: redeemScript}),
            type: Buffer.from(types.input.final_scriptsig, 'hex'),
          });

          pairs.push({
            value,
            type: Buffer.from(types.input.final_scriptwitness, 'hex'),
          });
        });
      }

      // Non-witness Multi-sig?
      if (isMultisig({script: n.redeem_script})) {
        const nullDummy = new BN(OP_0, decBase).toArrayLike(Buffer);
        const redeemScript = Buffer.from(n.redeem_script, 'hex');

        const redeemScriptPush = pushData({data: redeemScript});
        const [sigsRequired] = decompile(redeemScript);

        const requiredSignatureCount = sigsRequired - opNumberOffset;

        if (sigs.length !== requiredSignatureCount) {
          throw new Error('ExpectedAdditionalSignatures');
        }

        const components = [nullDummy].concat(sigs).concat([redeemScriptPush]);

        pairs.push({
          type: Buffer.from(types.input.final_scriptsig, 'hex'),
          value: Buffer.concat(components),
        });
      }

      // Witness P2SH Nested?
      if (!!n.redeem_script && !!n.witness_script) {
        pairs.push({
          type: Buffer.from(types.input.final_scriptsig, 'hex'),
          value: pushData({encode: n.redeem_script}),
        });
      }

      // Witness Multi-sig?
      if (isMultisig({script: n.witness_script})) {
        const nullDummy = new BN(OP_0, decBase).toArrayLike(Buffer);
        const witnessScript = Buffer.from(n.witness_script, 'hex');

        const [sigsRequired] = decompile(witnessScript);
        const witnessScriptPush = pushData({data: witnessScript});

        const requiredSignatureCount = sigsRequired - opNumberOffset;

        if (sigs.length !== requiredSignatureCount) {
          throw new Error('ExpectedAdditionalSignatures');
        }

        const components = [nullDummy].concat(sigs).concat(witnessScriptPush);

        const values = Buffer.concat(components);

        pairs.push({
          type: Buffer.from(types.input.final_scriptwitness, 'hex'),
          value: Buffer.concat([encode(components.length), values]),
        });
      }

      // Witness but non-multisig
      if (!!n.witness_script && !isMultisig({script: n.witness_script})) {
        const witnessScriptPush = pushData({encode: n.witness_script});

        const components = [].concat(sigs).concat(witnessScriptPush);

        if (Array.isArray(n.add_stack_elements)) {
          n.add_stack_elements.sort((a, b) => (a.index < b.index ? -1 : 1));

          n.add_stack_elements.forEach(({index, value}) => {
            const pushValue = Buffer.from(value, 'hex');

            const pushDataValue = Buffer.concat([
              encode(pushValue.length),
              pushValue,
            ]);

            return components.splice(index, 0, pushDataValue);
          });
        }

        const value = Buffer.concat([
          encode(components.length),
          Buffer.concat(components),
        ]);

        pairs.push({
          value,
          type: Buffer.from(types.input.final_scriptwitness, 'hex'),
        });
      } else if (!!redeem && !isWitness && !isP2shMultisig) {
        const signatures = n.partial_sig.map(n => {
          return encodeSignature({flag: n.hash_type, signature: n.signature});
        });

        const redeemScript = Buffer.from(n.redeem_script, 'hex');

        const components = [].concat(signatures).concat(redeemScript);

        if (Array.isArray(n.add_stack_elements)) {
          n.add_stack_elements.sort((a, b) => (a.index < b.index ? -1 : 1));

          n.add_stack_elements.forEach(({index, value}) => {
            return components.splice(index, 0, Buffer.from(value, 'hex'));
          });
        }

        if (!n.witness_utxo) {
          pairs.push({
            value: Buffer.concat(components.map(data => pushData({data}))),
            type: Buffer.from(types.input.final_scriptsig, 'hex'),
          });
        }
      }
    }

    addAttributes.filter(n => n.vin === vin).forEach(({type, value}) => {
      return pairs.push({
        type: Buffer.from(type, 'hex'),
        value: Buffer.from(value, 'hex'),
      });
    });

    return pairs.push({separator: true});
  });

  // Iterate through outputs to update output data
  tx.outs.forEach(({script}) => {
    const out = {};

    const [foundKey] = decompile(script)
      .filter(Buffer.isBuffer)
      .map(n => pubKeyHashes[n.toString('hex')])
      .filter(n => !!n);

    if (!!foundKey) {
      out.bip32_derivation = foundKey;
    }

    return outputs.push(!Object.keys(out).length ? null : out);
  });

  // Iterate through outputs to add pairs as appropriate
  tx.outs.forEach((out, vout) => {
    const output = outputs[vout] || decoded.outputs[vout] || {};

    if (!!output.bip32_derivation) {
      pairs.push({
        type: Buffer.concat([
          Buffer.from(types.output.bip32_derivation, 'hex'),
          Buffer.from(output.bip32_derivation.public_key, 'hex'),
        ]),
        value: Buffer.concat([
          Buffer.from(output.bip32_derivation.fingerprint, 'hex'),
          bip32Path({path: output.bip32_derivation.path}),
        ]),
      });
    }

    addAttributes.filter(n => n.vout === vout).forEach(({type, value}) => {
      return pairs.push({
        type: Buffer.from(type, 'hex'),
        value: Buffer.from(value, 'hex'),
      });
    });

    return pairs.push({separator: true});
  });

  return encodePsbt({pairs});
};
