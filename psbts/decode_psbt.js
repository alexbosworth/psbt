const BN = require('bn.js');
const varuint = require('varuint-bitcoin');

const {bip32Derivation} = require('./../bip32');
const {checkNonWitnessUtxo} = require('./../utxos');
const {checkWitnessUtxo} = require('./../utxos');
const {crypto} = require('./../tokens');
const {decodeSignature} = require('./../signatures');
const {keyCodeByteLength} = require('./constants');
const parseTaprootTree = require('./parse_taproot_tree');
const {script} = require('./../tokens');
const {sigHashByteLength} = require('./constants');
const {taprootBip32} = require('./../bip32');
const {tokensByteLength} = require('./constants');
const {Transaction} = require('./../tokens');
const types = require('./types');

const bufferAsHex = buffer => buffer.toString('hex');
const countGlobal = 1;
const {decompile} = script;
const globalSeparatorCode = parseInt(types.global.separator, 16);
const {hash160} = crypto;
const isControlBlockLength = n => n >= 33 && n <= 4129 && (n - 33) % 32 === 0;
const isSchnorrSignature = n => n.length === 64 || n.length === 65;
const lengthHash = 32;
const magicBytes = Buffer.from(types.global.magic);
const scriptForLeafScript = value => value.subarray(0, value.length - 1);
const tapScriptSigKeyTypeLength = 65;
const tapScriptSigEnd = 33;
const valueAsSchnorrSig = n => n.subarray(0, 64);
const valueAsSigHash = n => n.length === 64 ? 0 : n.readUInt8(64);
const versionForLeafScript = value => value.subarray(-1).readUInt8();
const xOnlyPublicKeyByteLength = 32;

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
        [leaf_hashes]: <Taproot Leaf Hash Hex String>
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
      [taproot_control_block]: <Taproot Script Spend Control Block Hex String>
      [taproot_leaf_hash]: <Taproot Leaf Hash Hex String>
      [taproot_leaf_public_key]: <Leaf Script X Only Public Key Hex String>
      [taproot_leaf_script]: <Taproot Leaf Spend Script Hex String>
      [taproot_leaf_version]: <Taproot Leaf Spend Script Version Number>
      [taproot_internal_key]: <X Only Taproot Internal Public Key Hex String>
      [taproot_key_spend_sig]: <Taproot Key Spend Signature Hex String>
      [taproot_root_hash]: <Taproot Merkle Root Hash Hex String>
      [taproot_script_signature]: <Taproot Script Spend Script Hex String>
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
        [leaf_hashes]: <Taproot Leaf Hash Hex String>
        path: <BIP 32 Child/HardenedChild/Index Derivation Path Hex String>
        public_key: <Public Key Hex String>
      }
      [redeem_script]: <Hex Encoded Redeem Script>
      [taproot_internal_key]: <X Only Taproot Internal Public Key Hex String>
      [taproot_script_tree]: [{
        depth: <Tree Depth Number>
        script: <Leaf Script Hex String>
        version: <Leaf Script Version Number>
      }]
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
  if (!ecp) {
    throw new Error('ExpectedEcpairLibraryToDecodePartiallySignedBitcoinTx');
  }

  if (!psbt) {
    throw new Error('ExpectedHexSerializedPartiallySignedBitcoinTransaction');
  }

  const buffer = Buffer.from(psbt, 'hex');
  const decoded = {inputs: [], outputs: [], pairs: []};
  const foundInputs = [];
  const foundOutputs = [];
  const globalKeys = {};
  let input;
  let inputIndex;
  let inputKeys = {};
  let isGlobal = true;
  let offset = 0;
  let output;
  let outputIndex;
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

        decoded.inputs[inputIndex] = input;

        input = null;
        inputIndex = null;
        inputKeys = {};
      }

      // Output detected and finished loading its values
      if (!!output) {
        decoded.outputs[outputIndex] = output;

        output = null;
        outputIndex = null;
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

        decoded.inputs = Array(tx.ins.length).fill({});
        decoded.outputs = Array(tx.outs.length).fill({});
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
        inputIndex = terminatorsFound - [globalKeys].length;
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

      case types.input.tap_bip32_derivation:
        input.bip32_derivations = input.bip32_derivations || [];

        input.bip32_derivations.push(taprootBip32({
          type: bufferAsHex(keyType),
          value: bufferAsHex(value),
        }));
        break;

      case types.input.tap_internal_key:
        if (value.length !== xOnlyPublicKeyByteLength) {
          throw new Error('ExpectedXOnlyPublicKeyForTapInternalKey');
        }

        input.taproot_internal_key = bufferAsHex(value);
        break;

      case types.input.tap_key_sig:
        if (!isSchnorrSignature(value)) {
          throw new Error('UnexpectedSizeOfTaprootKeySignature');
        }

        input.sighash_type = valueAsSigHash(value);
        input.taproot_key_spend_sig = bufferAsHex(valueAsSchnorrSig(value));
        break;

      case types.input.tap_leaf_script:
        const controlBlock = keyType.slice(keyCodeByteLength);

        if (!isControlBlockLength(controlBlock.length)) {
          throw new Error('ExpectedControlBlockForTapLeafScriptInput');
        }

        input.taproot_control_block = bufferAsHex(controlBlock);
        input.taproot_leaf_script = bufferAsHex(scriptForLeafScript(value));
        input.taproot_leaf_version = versionForLeafScript(value);
        break;

      case types.input.tap_merkle_root:
        if (value.length !== lengthHash) {
          throw new Error('UnexpectedSizeOfTaprootMerkleRootHashInInput');
        }

        input.taproot_root_hash = bufferAsHex(value);
        break;

      case types.input.tap_script_sig:
        if (keyType.length !== tapScriptSigKeyTypeLength) {
          throw new Error('UnexpectedSizeOfTaprootScriptSigKeyType');
        }

        if (!isSchnorrSignature(value)) {
          throw new Error('UnexpectedSizeOfTaprootScriptSignature');
        }

        const publicKey = keyType.subarray(keyCodeByteLength, tapScriptSigEnd);
        const leafHash = keyType.subarray(tapScriptSigEnd);

        input.sighash_type = valueAsSigHash(value);
        input.taproot_leaf_hash = bufferAsHex(leafHash);
        input.taproot_leaf_public_key = bufferAsHex(publicKey);
        input.taproot_script_signature = bufferAsHex(valueAsSchnorrSig(value));
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
        outputIndex = terminatorsFound - countGlobal - decoded.inputs.length;
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

      case types.output.tap_bip32_derivation:
        output.bip32_derivation = taprootBip32({
          type: bufferAsHex(keyType),
          value: bufferAsHex(value),
        });
        break;

      case types.output.tap_internal_key:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputTapInternalKeyTypeKey');
        }

        // Make sure that the value looks like an x-only public key
        if (value.length !== xOnlyPublicKeyByteLength) {
          throw new Error('InvalidOutputXOnlyPublicKeyForTapInternalKey');
        }

        output.taproot_internal_key = value.toString('hex');
        break;

      case types.output.tap_tree:
        const encoded = bufferAsHex(value);

        output.taproot_script_tree = parseTaprootTree({encoded}).tree;
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
