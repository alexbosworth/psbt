const {createHash} = require('node:crypto');

const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {numberAsCompactInt} = require('@alexbosworth/blockchain');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const {bip32Path} = require('./../bip32');
const {checkInputSighashTypes} = require('./../checks');
const {checkUpdateArguments} = require('./../checks');
const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
const {hash160} = require('./../spends');
const {inputSighashType} = require('./../spends');
const {inputSpentOutput} = require('./../spends');
const {isWitnessProgram} = require('./../utxos');
const {legacyTransactionComponents} = require('./../transactions');
const {matchingDerivations} = require('./../spends');
const mergePairs = require('./merge_pairs');
const {paidScripts} = require('./../spends');
const psbtSections = require('./psbt_sections');
const sighashAsBuffer = require('./sighash_as_buffer');
const {tokensByteLength} = require('./constants');
const {transactionId} = require('./../transactions');
const types = require('./types');
const {witnessProgram} = require('./../utxos');

const asElements = script => scriptAsScriptElements({script}).elements || [];
const bufferAsHex = buffer => buffer.toString('hex');
const byPublicKey = (a, b) => a.public_key < b.public_key ? -1 : 1;
const encode = number => numberAsCompactInt({number}).encoded;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isBuffer} = Buffer;
const key = (type, data) => Buffer.concat([Buffer.from(type, 'hex'), data]);
const scriptOf = hex => hex === undefined ? hex : Buffer.from(hex, 'hex');
const sha256 = data => createHash('sha256').update(data).digest();
const versionZero = 0;

/** Update a PSBT

  Everything already in the PSBT is kept. Supplied values are added, and they
  replace an existing value that has the same key.

  Scripts and derivations are matched to the output that each input spends and
  to each output. Derivations are only added for keys that the scripts check
  signatures with.

  A supplied funding transaction is added as the witness UTXO of a witness
  output, and as the full transaction of a legacy or version 0 witness output,
  so that signers can check the amount being spent.

  The sighash type of an input is chosen once every change to the input is
  merged, including additional attributes. An input with a sighash type after
  the changes keeps it, and all of its signatures must use it. Otherwise,
  supplied signatures give the input the sighash type that all of its
  signatures share, or no sighash type when they use different ones. Taproot
  signatures do not set a sighash type.

  {
    [additional_attributes]: [{
      type: <Type Hex String>
      value: <Value Hex String>
      [vin]: <Input Index Number>
      [vout]: <Output Index Number>
    }]
    [bip32_derivations]: [{
      fingerprint: <BIP 32 Fingerprint of Parent's Key Hex String>
      [path]: <BIP 32 Derivation Path String>
      public_key: <Public Key Hex String>
    }]
    psbt: <BIP 174 Encoded PSBT String>
    [redeem_scripts]: [<Hex Encoded Redeem Script String>]
    [sighashes]: [{
      id: <Transaction Id String>
      sighash: <Sighash Flag Number>
      vout: <Spending Output Index Number>
    }]
    [signatures]: [{
      [hash_type]: <Signature Hash Type Number>
      public_key: <Public Key Hex String>
      signature: <Signature Hex String>
      vin: <Signature Input Index Number>
    }]
    [taproot_inputs]: [{
      [key_spend_sig]: <Taproot Key Spend Signature Hex String>
      vin: <Input Index Number>
    }]
    [transactions]: [<Hex Encoded Transaction String>]
    [witness_scripts]: [<Witness Script Hex String>]
  }

  @throws
  <Update PSBT Error>

  @returns
  {
    psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
  }
*/
module.exports = args => {
  if (!args.psbt) {
    throw new Error('ExpectedPsbtToUpdate');
  }

  const decoded = decodePsbt({psbt: args.psbt});
  const derivations = new Map();
  const fundings = new Map();
  const globalAttributes = [];
  const knownFundings = new Map();
  const pairs = [];
  const pushed = new Map();
  const redeems = new Map();
  const sighashes = new Map();
  const taprootInputs = new Map();
  const witnesses = new Map();

  const {sections} = psbtSections({psbt: args.psbt});

  // The existing pairs of each section are the starting point of the update
  const [globalPairs, ...maps] = sections;

  const tx = legacyTransactionComponents({
    transaction: decoded.unsigned_transaction,
  });

  // Arguments are checked before anything is encoded
  checkUpdateArguments({transaction: tx, update: args});

  const inputAttributes = tx.inputs.map(() => []);
  const inputPairs = maps.slice(0, tx.inputs.length);
  const outputAttributes = tx.outputs.map(() => []);
  const outputPairs = maps.slice(tx.inputs.length);
  const signatures = tx.inputs.map(() => []);

  // Group the additional attributes by section once
  (args.additional_attributes || []).forEach(({type, value, vin, vout}) => {
    const pair = {type: hexAsBuffer(type), value: hexAsBuffer(value)};

    if (vin !== undefined) {
      return inputAttributes[vin].push(pair);
    }

    if (vout !== undefined) {
      return outputAttributes[vout].push(pair);
    }

    return globalAttributes.push(pair);
  });

  // Existing global pairs are kept, with additional global attributes set
  const {section: globalSection} = mergePairs({
    order: types.order.global,
    pairs: globalAttributes,
    section: globalPairs,
  });

  globalSection.forEach(n => pairs.push(n));

  pairs.push({separator: true});

  // Index derivations by public key and by public key hash, as lowercase hex
  (args.bip32_derivations || []).forEach(n => {
    const publicKey = hexAsBuffer(n.public_key);

    const derivation = {
      fingerprint: n.fingerprint,
      path: n.path,
      public_key: bufferAsHex(publicKey),
    };

    derivations.set(derivation.public_key, derivation);
    derivations.set(bufferAsHex(hash160({data: publicKey})), derivation);

    return;
  });

  // Index sighashes by spending outpoint
  (args.sighashes || []).forEach(n => {
    return sighashes.set(`${n.id.toLowerCase()}:${n.vout}`, n.sighash);
  });

  // Group signatures by the input that they sign
  (args.signatures || []).forEach(n => signatures[n.vin].push(n));

  // Index taproot inputs by the input that they are for
  (args.taproot_inputs || []).forEach(n => taprootInputs.set(n.vin, n));

  // Index supplied funding transactions by id, parsing each one only once
  (args.transactions || []).forEach(transaction => {
    let funding;

    try {
      funding = componentsOfTransaction({transaction});
    } catch (err) {
      throw new Error('ExpectedValidTransactionToUpdatePsbt');
    }

    const {id} = transactionId(funding);

    return fundings.set(id, {transaction, outputs: funding.outputs});
  });

  // Index redeem scripts by their hashes
  (args.redeem_scripts || []).forEach(hex => {
    const [push] = asElements(hex);
    const script = hexAsBuffer(hex);

    redeems.set(bufferAsHex(hash160({data: script})), script);

    // A redeem script can also be given as a push of the redeem script
    if (!isBuffer(push)) {
      return;
    }

    return pushed.set(bufferAsHex(hash160({data: push})), push);
  });

  // Index witness scripts by their hashes
  (args.witness_scripts || []).forEach(hex => {
    const script = hexAsBuffer(hex);

    return witnesses.set(bufferAsHex(sha256(script)), script);
  });

  // Derivations and scripts are matched to the outputs that inputs spend
  const isMatching = !!derivations.size || !!redeems.size || !!witnesses.size;

  // Full funding transactions already in the PSBT are parsed once each
  decoded.inputs.forEach((input, vin) => {
    const {id} = tx.inputs[vin];

    // A full funding transaction is used when no other record has the output
    const isUsed = !fundings.has(id) && !input.witness_utxo;

    if (!isMatching || !isUsed || !input.non_witness_utxo) {
      return;
    }

    // Inputs that spend from the same transaction share its parsed outputs
    if (knownFundings.has(id)) {
      return;
    }

    const funding = componentsOfTransaction({
      transaction: input.non_witness_utxo,
    });

    return knownFundings.set(id, funding.outputs);
  });

  // Iterate through transaction inputs to find the values to set
  const updates = tx.inputs.map((input, vin) => {
    const records = decoded.inputs[vin];
    const supplied = fundings.get(input.id);
    const update = {};

    update.partial_sig = signatures[vin];
    update.sighash_type = sighashes.get(`${input.id}:${input.vout}`);

    // Exit early when there is nothing to find for the output being spent
    if (!isMatching && !supplied) {
      return update;
    }

    const spent = inputSpentOutput({
      known: knownFundings.get(input.id),
      supplied: !!supplied ? supplied.outputs : undefined,
      vout: input.vout,
      witness_utxo: records.witness_utxo,
    });

    // Exit early when there is no spent output script, which can be empty
    if (spent.script === undefined) {
      return update;
    }

    const script = hexAsBuffer(spent.script);

    // Scripts are matched only to the output that the input spends
    const {redeem, witness} = paidScripts({
      pushed,
      redeems,
      script,
      witnesses,
      known_redeem: scriptOf(records.redeem_script),
      known_witness: scriptOf(records.witness_script),
    });

    update.redeem_script = redeem;
    update.witness_script = witness;

    // Derivations are for keys that the input scripts check signatures with
    const matching = matchingDerivations({
      derivations,
      scripts: [script, redeem, witness].filter(n => !!n),
    });

    update.bip32_derivations = matching.derivations;

    // Exit early when there is no supplied funding transaction to add
    if (!supplied) {
      return update;
    }

    const isNested = !!redeem && isWitnessProgram({script: redeem});

    // The output is a witness output when its script or redeem script is one
    const isWitness = isWitnessProgram({script}) || isNested;

    const {version} = witnessProgram({script: isNested ? redeem : script});

    if (isWitness) {
      update.witness_utxo = {script_pub: spent.script, tokens: spent.tokens};
    }

    // Signers check the amount of a version 0 witness output by its funding
    if (!isWitness || version === versionZero) {
      update.non_witness_utxo = supplied.transaction;
    }

    return update;
  });

  // Encode inputs into key value pairs
  const inputSections = updates.map((update, vin) => {
    const taprootInput = taprootInputs.get(vin);
    const values = [];

    // Legacy UTXO being spent by this input
    if (!!update.non_witness_utxo) {
      values.push({
        type: hexAsBuffer(types.input.non_witness_utxo),
        value: hexAsBuffer(update.non_witness_utxo),
      });
    }

    // Witness UTXO being spent by this input
    if (!!update.witness_utxo) {
      const script = hexAsBuffer(update.witness_utxo.script_pub);

      const tokens = Buffer.alloc(tokensByteLength);

      tokens.writeBigUInt64LE(BigInt(update.witness_utxo.tokens));

      values.push({
        type: hexAsBuffer(types.input.witness_utxo),
        value: Buffer.concat([tokens, encode(script.length), script]),
      });
    }

    // Partial signatures, each for the exact public key it was made with
    update.partial_sig.forEach(n => {
      return values.push({
        type: key(types.input.partial_sig, hexAsBuffer(n.public_key)),
        value: hexAsBuffer(n.signature),
      });
    });

    // A new taproot key spend signature replaces an existing one
    if (!!taprootInput && !!taprootInput.key_spend_sig) {
      values.push({
        type: hexAsBuffer(types.input.tap_key_sig),
        value: hexAsBuffer(taprootInput.key_spend_sig),
      });
    }

    // Sighash type supplied for this input
    if (update.sighash_type !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.sighash_type),
        value: sighashAsBuffer({sighash: update.sighash_type}),
      });
    }

    // Redeem script used in the scriptsig of this input, which can be empty
    if (update.redeem_script !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.redeem_script),
        value: update.redeem_script,
      });
    }

    // Witness script used in this input, which can be empty
    if (update.witness_script !== undefined) {
      values.push({
        type: hexAsBuffer(types.input.witness_script),
        value: update.witness_script,
      });
    }

    // Bip 32 derivations for this input, in order of public key
    (update.bip32_derivations || []).sort(byPublicKey).forEach(n => {
      const path = bip32Path({path: n.path});

      return values.push({
        type: key(types.input.bip32_derivation, hexAsBuffer(n.public_key)),
        value: Buffer.concat([hexAsBuffer(n.fingerprint), path]),
      });
    });

    // The new values are set over the existing pairs of the input
    const {section} = mergePairs({
      order: types.order.input,
      pairs: values,
      section: inputPairs[vin],
    });

    // Additional attributes are set over all of the other input pairs
    const {section: merged} = mergePairs({
      order: types.order.input,
      pairs: inputAttributes[vin],
      section,
    });

    // Exit early when no signatures are added to set a sighash type with
    if (!update.partial_sig.length) {
      return merged;
    }

    // The sighash type is chosen once every change to the input is merged
    const {sighash_type} = inputSighashType({pairs: merged});

    // Exit early when the input has a sighash type or the signatures differ
    if (sighash_type === undefined) {
      return merged;
    }

    // The input gets the sighash type that all of its signatures share
    const {section: signed} = mergePairs({
      order: types.order.input,
      pairs: [{
        type: hexAsBuffer(types.input.sighash_type),
        value: sighashAsBuffer({sighash: sighash_type}),
      }],
      section: merged,
    });

    return signed;
  });

  // Each input section follows the global section and ends with a separator
  inputSections.forEach(section => {
    section.forEach(n => pairs.push(n));

    return pairs.push({separator: true});
  });

  // Iterate through outputs to update output data
  tx.outputs.forEach((output, vout) => {
    const records = decoded.outputs[vout];
    const script = hexAsBuffer(output.script);
    const values = [];

    // Scripts are matched to the output script
    const {redeem, witness} = paidScripts({
      pushed,
      redeems,
      script,
      witnesses,
      known_redeem: scriptOf(records.redeem_script),
      known_witness: scriptOf(records.witness_script),
    });

    // Redeem script that the output pays to, which can be empty
    if (redeem !== undefined) {
      values.push({
        type: hexAsBuffer(types.output.redeem_script),
        value: redeem,
      });
    }

    // Witness script that the output pays to, which can be empty
    if (witness !== undefined) {
      values.push({
        type: hexAsBuffer(types.output.witness_script),
        value: witness,
      });
    }

    // Derivations are for keys that the output scripts check signatures with
    const {derivations: found} = matchingDerivations({
      derivations,
      scripts: [script, redeem, witness].filter(n => !!n),
    });

    found.sort(byPublicKey).forEach(n => {
      const path = bip32Path({path: n.path});

      return values.push({
        type: key(types.output.bip32_derivation, hexAsBuffer(n.public_key)),
        value: Buffer.concat([hexAsBuffer(n.fingerprint), path]),
      });
    });

    const {section} = mergePairs({
      order: types.order.output,
      pairs: values,
      section: outputPairs[vout],
    });

    // Additional attributes are set over all of the other output pairs
    const {section: outputSection} = mergePairs({
      order: types.order.output,
      pairs: outputAttributes[vout],
      section,
    });

    outputSection.forEach(n => pairs.push(n));

    return pairs.push({separator: true});
  });

  // The updated PSBT must be a valid PSBT
  const {psbt} = encodePsbt({pairs});

  // Signatures must use the sighash type of their input after every change
  inputSections.forEach(section => checkInputSighashTypes({pairs: section}));

  return {psbt};
};
