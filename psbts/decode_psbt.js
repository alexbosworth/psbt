const BN = require('bn.js');
const varuint = require('varuint-bitcoin')

const {bip32Derivation} = require('./../bip32');
const {checkNonWitnessUtxo} = require('./../utxos');
const {checkWitnessUtxo} = require('./../utxos');
const {crypto} = require('./../tokens');
const {decodeSignature} = require('./../signatures');
const {keyCodeByteLength} = require('./constants');
const {script} = require('./../tokens');
const {sigHashByteLength} = require('./constants');
const {tokensByteLength} = require('./constants');
const {Transaction} = require('./../tokens');
const types = require('./types');

const {decompile} = script;
const globalSeparatorCode = parseInt(types.global.separator, 16);
const magicBytes = Buffer.from(types.global.magic);
const {hash160} = crypto;

/** Decode a BIP 174 encoded PSBT

  {
    ecp: <ECPair Object>
    psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
  }

  @throws
  <Invalid PSBT Error>

  @returns
  {
    inputs: [{
       [bip32_derivations]: [{
          fingerprint: <Public Key Fingerprint Hex String>
          path: <BIP 32 Child / Hardened Child / Index Derivation Path String>
          public_key: <Public Key Hex String>
      }]
      [final_scriptsig]: <Final ScriptSig Hex String>
      [final_scriptwitness]: <Final Script Witness Hex String>
      [non_witness_utxo]: <Non-Witness Hex Encoded Transaction String>
      [partial_sig]: [{
        hash_type: <Signature Hash Type Number>
        public_key: <Public Key Hex String>
        signature: <Signature Hex String>
      }]
      [redeem_script]: <Hex Encoded Redeem Script String>
      [sighash_type]: <Sighash Type Number>
      [unrecognized_attributes]: [{
        type: <Key Type Hex String>
        value: <Value Hex String>
      }]
      [witness_script]: <Witness Script Hex String>
      [witness_utxo]: {
        script_pub: <UTXO ScriptPub Hex String>
        tokens: <Tokens Number>
      }
    }]
    outputs: [{
      [bip32_derivation]: {
        fingerprint: <Public Key Fingerprint Hex String>
        path: <BIP 32 Child/HardenedChild/Index Derivation Path Hex String>
        public_key: <Public Key Hex String>
      }
      [redeem_script]: <Hex Encoded Redeem Script>
      [unrecognized_attributes]: [{
        type: <Key Type Hex String>
        value: <Value Hex String>
      }]
      [witness_script]: <Hex Encoded Witness Script>
    }]
    pairs: [{
      type: <Key Type Hex String>
      value: <Value Hex String>
    }]
    [unrecognized_attributes]: [{
      type: <Global Key Type Hex String>
      value: <Global Value Hex String>
    }]
    unsigned_transaction: <Unsigned Transaction Hex String>
  }
*/
module.exports = ({ecp, psbt}) => {
  if (!psbt) {
    throw new Error('ExpectedHexSerializedPartiallySignedBitcoinTransaction');
  }

  const buffer = Buffer.from(psbt, 'hex');
  const decoded = {inputs: [], outputs: [], pairs: []};
  const foundInputs = [];
  const foundOutputs = [];
  const globalKeys = {};
  let input;
  let inputKeys = {};
  let isGlobal = true;
  let offset = 0;
  let output;
  let outputKeys = {};
  let terminatorsExpected;
  let terminatorsFound = 0;

  // Buffer read methods
  const read = bytesCount => {
    offset += bytesCount;

    return buffer.slice(offset - bytesCount, offset);
  };
  const readCompactVarInt = () => {
    const n = varuint.decode(buffer, offset);

    offset += varuint.decode.bytes;

    return n;
  };

  // Start reading - beginning with magic bytes
  const magicValue = read(magicBytes.length);

  // The magic bytes of a psbt must always be set
  if (!magicValue.equals(magicBytes)) {
    throw new Error('UnrecognizedMagicBytes');
  }

  const globalSeparator = buffer.readUInt8(offset++);

  // After the magic bytes must come a global separator
  if (globalSeparator !== globalSeparatorCode) {
    throw new Error('ExpectedGlobalSeparator');
  }

  // Read through key/value pairs
  while (offset < buffer.length) {
    // KeyType bytes are variable length
    const keyTypeLength = readCompactVarInt();

    // An unsigned transaction must come first
    if (!keyTypeLength && !decoded.unsigned_transaction) {
      throw new Error('ExpectedUnsignedTransaction');
    }

    // End markers are zero
    if (!keyTypeLength) {
      isGlobal = false;
      terminatorsFound++;

      // Check non-witness UTXO input redeem scripts
      if (!!input && !!input.non_witness_utxo && !!input.redeem_script) {
        try {
          checkNonWitnessUtxo({
            hash: input.redeem_script_hash,
            script: Buffer.from(input.redeem_script, 'hex'),
            utxo: Buffer.from(input.non_witness_utxo, 'hex'),
          });
        } catch (err) {
          throw err;
        }
      }

      // Check witness UTXO
      if (!!input && !!input.witness_utxo) {
        try {
          checkWitnessUtxo({
            hash: input.witness_script_hash,
            redeem: input.redeem_script,
            script: input.witness_utxo.script_pub,
          });
        } catch (err) {
          throw err;
        }
      }

      // A valid input was fully parsed
      if (!!input) {
        delete input.redeem_script_hash;
        delete input.witness_script_hash;

        decoded.inputs.push(input);

        input = null;
        inputKeys = {};
      }

      // Output detected and finished loading its values
      if (!!output) {
        decoded.outputs.push(output);

        output = null;
        outputKeys = {};
      }

      continue;
    }

    // Keys are variable length data
    const keyType = read(keyTypeLength);

    // The key code defines what "type" a key/pair is
    const keyCode = keyType.slice(0, keyCodeByteLength);

    const keyTypeCode = keyCode.toString('hex');

    // Values are variable length data
    const value = read(readCompactVarInt());

    if (isGlobal) {
      switch (keyType.toString('hex')) {
      case types.global.unsigned_tx:
        if (!!decoded.unsigned_transaction) {
          throw new Error('InvalidGlobalTransactionKeyType');
        }

        const tx = Transaction.fromBuffer(value);
        decoded.unsigned_transaction = value.toString('hex');

        terminatorsExpected = tx.ins.length + tx.outs.length + [tx].length;

        tx.ins.forEach(n => {
          if (!!n.script.length) {
            throw new Error('ExpectedEmptyScriptSigs')
          }

          if (!!n.witness.length) {
            throw new Error('ExpectedEmptyWitnesses');
          }

          foundInputs.push(n);
        });

        tx.outs.forEach(n => foundOutputs.push(n));
        break;

      default:
        if (!decoded.unsigned_transaction) {
          throw new Error('InvalidGlobalTransactionKeyType');
        }

        const type = keyType.toString('hex');
        const unrecognized = decoded.unrecognized_attributes || [];

        if (!!globalKeys[type] || type === types.global.unsigned_tx) {
          throw new Error('UnexpectedDuplicateGlobalKey');
        }

        decoded.unrecognized_attributes = unrecognized;
        globalKeys[type] = true;

        decoded.unrecognized_attributes.push({
          type,
          value: value.toString('hex'),
        });
        break;
      }
    } else if (!!foundInputs.length || !!input) {
      // Start of a new input?
      if (!input) {
        foundInputs.pop();
        input = {};
      }

      if (!!inputKeys[keyType.toString('hex')]) {
        throw new Error('UnexpectedDuplicateInputKey');
      }

      // Keep track of input keys to make sure there's no duplicates
      inputKeys[keyType.toString('hex')] = true;

      switch (keyTypeCode) {
      case types.input.bip32_derivation:
        input.bip32_derivations = input.bip32_derivations || [];

        let bip32;
        const derivation = value;
        const key = keyType.slice([keyTypeCode].length);

        try {
          bip32 = bip32Derivation({derivation, ecp, key});
        } catch (err) {
          throw err;
        }

        input.bip32_derivations.push(bip32);
        break;

      case types.input.final_scriptsig:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidFinalScriptSigKey');
        }

        // Check to make sure that the scriptsig is a reasonable script
        if (!decompile(value)) {
          throw new Error('InvalidFinalScriptSig');
        }

        input.final_scriptsig = value.toString('hex');
        break;

      case types.input.final_scriptwitness:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidScriptWitnessTypeKey');
        }

        const byteLength = varuint.decode(value);

        const scriptWitness = value.slice(varuint.decode.bytes);

        // Check to make sure that the final script witness is valid script
        if (!decompile(scriptWitness)) {
          throw new Error('InvalidScriptWitness');
        }

        input.final_scriptwitness = scriptWitness.toString('hex');
        break;

      case types.input.non_witness_utxo:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidNonWitnessUtxoTypeKey');
        }

        try {
          Transaction.fromBuffer(value);
        } catch (err) {
          throw new Error('ExpectedValidTransactionForNonWitnessUtxo');
        }

        if (input.witness_utxo) {
          throw new Error('UnexpectedDuplicateSpendForInput');
        }

        input.non_witness_utxo = value.toString('hex');
        break;

      case types.input.partial_sig:
        let sigPubKey;
        let signature;

        try {
          signature = decodeSignature({signature: value});
        } catch (err) {
          throw new Error('ExpectedValidPartialSignature');
        }

        // Make sure the partial signature public key is a valid pubkey
        try {
          sigPubKey = ecp.fromPublicKey(keyType.slice(keyCodeByteLength));
        } catch (err) {
          throw new Error('InvalidPublicKeyForPartialSig');
        }

        input.partial_sig = input.partial_sig || [];

        input.partial_sig.push({
          hash_type: signature.hash_type,
          public_key: sigPubKey.publicKey.toString('hex'),
          signature: signature.signature.toString('hex'),
        });
        break;

      case types.input.redeem_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidRedeemScriptTypeKey');
        }

        // Make sure the redeem script is a reasonable script
        if (!decompile(value)) {
          throw new Error('InvalidRedeemScript');
        }

        input.redeem_script = value.toString('hex');
        input.redeem_script_hash = hash160(value);
        break;

      case types.input.sighash_type:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidSigHashTypeKey');
        }

        if (value.length !== sigHashByteLength) {
          throw new Error('UnexpectedSigHashTypeByteLength');
        }

        input.sighash_type = value.readUInt32LE();
        break;

      case types.input.witness_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidWitnessScriptTypeKey');
        }

        // Make sure that the witness script is a reasonable script
        if (!decompile(value)) {
          throw new Error('InvalidWitnessScript');
        }

        input.witness_script = value.toString('hex');
        input.witness_script_hash = crypto.sha256(value);
        break;

      case types.input.witness_utxo:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidInputWitnessUtxoTypeKey');
        }

        const scriptPubKeyLen = varuint.decode(value.slice(tokensByteLength));

        const scriptPub = value.slice(tokensByteLength + varuint.decode.bytes);

        let tokens;

        try {
          tokens = new BN(value.slice(0, tokensByteLength), 'le').toNumber();
        } catch (err) {
          throw new Error('ExpectedValidTokensNumber');
        }

        input.witness_utxo = {tokens, script_pub: scriptPub.toString('hex')};
        break;

      default:
        input.unrecognized_attributes = input.unrecognized_attributes || [];

        input.unrecognized_attributes.push({
          type: keyType.toString('hex'),
          value: value.toString('hex'),
        });
        break;
      }
    } else if (!!foundOutputs.length || !!output) {
      if (!output) {
        foundOutputs.pop();
        output = {};
      }

      if (!!outputKeys[keyType.toString('hex')]) {
        throw new Error('UnexpectedDuplicateInputKey');
      }

      // Keep track of the output key to guard against duplicates
      outputKeys[keyType.toString('hex')] = true;

      switch (keyTypeCode) {
      case types.output.bip32_derivation:
        const derivation = value;
        const key = keyType.slice([keyTypeCode].length);

        try {
          output.bip32_derivation = bip32Derivation({derivation, ecp, key});
        } catch (err) {
          throw err;
        }
        break;

      case types.output.redeem_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputRedeemScriptTypeKey');
        }

        // Make sure that the redeem script is a reasonable script
        if (!decompile(value)) {
          throw new Error('InvalidOutputRedeemScript');
        }

        output.redeem_script = value.toString('hex');
        break;

      case types.output.witness_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputWitnessScriptTypeKey');
        }

        // Make sure that the witness script is a reasonable script
        if (!decompile(value)) {
          throw new Error('InvalidOutputWitnessScript');
        }

        output.witness_script = value.toString('hex');
        break;

      default:
        output.unrecognized_attributes = output.unrecognized_attributes || [];

        output.unrecognized_attributes.push({
          type: keyType.toString('hex'),
          value: value.toString('hex'),
        });
        break;
      }
    }

    decoded.pairs.push({
      type: keyType.toString('hex'),
      value: value.toString('hex'),
    });
  }

  if (terminatorsExpected !== terminatorsFound) {
    throw new Error('ExpectedAdditionalOutputs');
  }

  return decoded;
};
