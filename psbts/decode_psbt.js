const {createHash} = require('node:crypto');

const {compactIntAsNumber} = require('@alexbosworth/blockchain');
const {componentsOfTransaction} = require('@alexbosworth/blockchain');
const {isPoint} = require('tiny-secp256k1');
const {scriptAsScriptElements} = require('@alexbosworth/blockchain');

const {bip32Derivation} = require('./../bip32');
const {checkGlobalXpub} = require('./../checks');
const {checkNonWitnessUtxo} = require('./../utxos');
const {checkOutputScripts} = require('./../checks');
const {checkPreimage} = require('./../checks');
const {checkProprietaryKey} = require('./../checks');
const {checkWitnessUtxo} = require('./../utxos');
const {decodeSignature} = require('./../signatures');
const {ecdsaSigHashTypes} = require('./constants');
const {hash160} = require('./../spends');
const {isLeafVersion} = require('./../checks');
const {keyCodeByteLength} = require('./constants');
const {legacyTransactionComponents} = require('./../transactions');
const {parseTaprootTree} = require('./../checks');
const {parseWitnessElements} = require('./../transactions');
const {readCompactSize} = require('./../transactions');
const {sigHashByteLength} = require('./constants');
const {tapSigHashTypes} = require('./constants');
const {taprootBip32} = require('./../bip32');
const {taprootLeafVersionMask} = require('./constants');
const {taprootOutputKey} = require('./../utxos');
const {tokensAsNumber} = require('./../transactions');
const {tokensByteLength} = require('./constants');
const {transactionId} = require('./../transactions');
const types = require('./types');

const asElements = script => scriptAsScriptElements({script}).elements;
const bufferAsHex = buffer => buffer.toString('hex');
const countGlobal = 1;
const globalSeparatorCode = parseInt(types.global.separator, 16);
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const isControlBlockLength = n => n >= 33 && n <= 4129 && (n - 33) % 32 === 0;
const isHex = n => !(n.length % 2) && /^[0-9a-f]*$/i.test(n);
const isSchnorrSignature = n => n.length === 64 || n.length === 65;
const isTapSigHash = n => n.length === 64 || tapSigHashTypes.includes(n[64]);
const lengthHash = 32;
const magicBytes = Buffer.from(types.global.magic);
const scriptForLeafScript = value => value.subarray(0, value.length - 1);
const sha256 = n => createHash('sha256').update(n).digest();
const supportedVersion = 0;
const tapScriptSigKeyTypeLength = 65;
const tapScriptSigEnd = 33;
const valueAsSchnorrSig = n => n.subarray(0, 64);
const valueAsSigHash = n => n.length === 64 ? 0 : n.readUInt8(64);
const versionByteLength = 4;
const versionForLeafScript = value => value.subarray(-1).readUInt8();
const xOnlyPublicKeyByteLength = 32;

/** Decode a BIP 174 encoded PSBT

  A final script witness is returned as its length prefixed elements, without
  the count of elements that comes before them in the PSBT.

  {
    psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
  }

  @throws
  <Invalid PSBT Error>

  @returns
  {
    inputs: [{
      [bip32_derivations]: [{
        fingerprint: <Public Key Fingerprint Hex String>
        [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
        [path]: <BIP 32 Child / Hardened Child / Index Derivation Path String>
        public_key: <Public Key Hex String>
      }]
      [final_scriptsig]: <Final ScriptSig Hex String>
      [final_scriptwitness]: <Witness Elements Without Count Hex String>
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
      [taproot_leaf_scripts]: [{
        control_block: <Taproot Script Spend Control Block Hex String>
        script: <Taproot Leaf Spend Script Hex String>
        version: <Taproot Leaf Spend Script Version Number>
      }]
      [taproot_leaf_version]: <Taproot Leaf Spend Script Version Number>
      [taproot_internal_key]: <X Only Taproot Internal Public Key Hex String>
      [taproot_key_spend_sig]: <Taproot Key Spend Signature Hex String>
      [taproot_key_spend_sig_hash_type]: <Key Spend Signature Sighash Number>
      [taproot_root_hash]: <Taproot Merkle Root Hash Hex String>
      [taproot_script_signature]: <Taproot Script Spend Signature Hex String>
      [taproot_script_signatures]: [{
        hash_type: <Signature Sighash Type Number>
        leaf_hash: <Taproot Leaf Hash Hex String>
        public_key: <Leaf Script X Only Public Key Hex String>
        signature: <Taproot Script Spend Signature Hex String>
      }]
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
        [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
        [path]: <BIP 32 Child/HardenedChild/Index Derivation Path String>
        public_key: <Public Key Hex String>
      }
      [bip32_derivations]: [{
        fingerprint: <Public Key Fingerprint Hex String>
        [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
        [path]: <BIP 32 Child/HardenedChild/Index Derivation Path String>
        public_key: <Public Key Hex String>
      }]
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
module.exports = ({psbt}) => {
  // Check all of the hex so that no malformed characters are silently dropped
  if (!psbt || typeof psbt !== 'string' || !isHex(psbt)) {
    throw new Error('ExpectedHexSerializedPartiallySignedBitcoinTransaction');
  }

  const buffer = hexAsBuffer(psbt);
  const decoded = {inputs: [], outputs: [], pairs: []};
  const foundInputs = [];
  const foundOutputs = [];
  const globalKeys = {};
  const parents = new Map();
  const publicKeys = new Map();
  let hasTaprootFields = false;
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
  let transactionInputs = [];
  let transactionOutputs = [];

  // Buffer read methods
  const read = bytesCount => {
    // Fields must contain all of the bytes that their lengths promise
    if (bytesCount > buffer.length - offset) {
      throw new Error('ExpectedMoreBytesForPsbtKeyOrValue');
    }

    offset += bytesCount;

    return buffer.slice(offset - bytesCount, offset);
  };

  // A public key that is used more than once is validated once
  const isPublicKey = key => {
    const id = bufferAsHex(key);

    if (!publicKeys.has(id)) {
      publicKeys.set(id, isPoint(key));
    }

    return publicKeys.get(id);
  };

  const readCompactVarInt = () => {
    const n = compactIntAsNumber({encoded: buffer, start: offset});

    offset += n.bytes;

    return n.number;
  };

  // Start reading - beginning with magic bytes
  const magicValue = buffer.slice(offset, magicBytes.length);

  offset += magicBytes.length;

  // The magic bytes of a psbt must always be set
  if (!magicValue.equals(magicBytes)) {
    throw new Error('UnrecognizedMagicBytes');
  }

  const globalSeparator = buffer[offset++];

  // After the magic bytes must come a global separator
  if (globalSeparator !== globalSeparatorCode) {
    throw new Error('ExpectedGlobalSeparator');
  }

  // Read through key/value pairs
  while (offset < buffer.length) {
    // Nothing is allowed after the final section
    if (terminatorsFound === terminatorsExpected) {
      throw new Error('UnexpectedDataAfterFinalPsbtSection');
    }

    // KeyType bytes are variable length
    const keyTypeLength = readCompactVarInt();

    // The global section must include an unsigned transaction
    if (!keyTypeLength && !decoded.unsigned_transaction) {
      throw new Error('ExpectedUnsignedTransaction');
    }

    // End markers are zero
    if (!keyTypeLength) {
      // Count every input and output section as it ends, even when empty
      if (!isGlobal && !!foundInputs.length) {
        foundInputs.pop();
      } else if (!isGlobal) {
        foundOutputs.pop();
      }

      isGlobal = false;
      terminatorsFound++;

      const hasRedeem = !!input && input.redeem_script !== undefined;
      const hasUtxoTx = !!input && !!input.non_witness_utxo;
      const hasWitness = !!input && !!input.witness_script_hash;

      // Check non-witness UTXO input scripts against the spent output
      if (hasUtxoTx && (hasRedeem || hasWitness)) {
        const {vout} = transactionInputs[inputIndex];

        checkNonWitnessUtxo({
          hash: input.redeem_script_hash,
          output: input.non_witness_utxo_outputs[vout],
          redeem: input.redeem_script,
          witness: input.witness_script_hash,
        });
      }

      // Check witness UTXO
      if (!!input && !!input.witness_utxo) {
        checkWitnessUtxo({
          hash: input.witness_script_hash,
          redeem: input.redeem_script,
          script: input.witness_utxo.script_pub,
        });
      }

      // Both records of the output being spent must describe the same output
      if (hasUtxoTx && !!input.witness_utxo) {
        const {vout} = transactionInputs[inputIndex];

        const spent = input.non_witness_utxo_outputs[vout];

        const isSameScript = spent.script === input.witness_utxo.script_pub;
        const isSameTokens = spent.tokens === input.witness_utxo.tokens;

        if (!isSameScript || !isSameTokens) {
          throw new Error('WitnessUtxoDoesNotMatchNonWitnessUtxo');
        }
      }

      let spentScript;

      // The output that an input spends is known from either UTXO record
      if (!!input && !!input.witness_utxo) {
        spentScript = input.witness_utxo.script_pub;
      } else if (!!input && !!input.non_witness_utxo_outputs) {
        const {vout} = transactionInputs[inputIndex];

        spentScript = input.non_witness_utxo_outputs[vout].script;
      }

      // Taproot fields of an input are for spending a taproot output
      if (hasTaprootFields && spentScript !== undefined) {
        const {output_key} = taprootOutputKey({script: spentScript});

        if (!output_key) {
          throw new Error('UnexpectedTaprootFieldForNonTaprootInput');
        }
      }

      hasTaprootFields = false;

      // A valid input was fully parsed
      if (!!input) {
        delete input.non_witness_utxo_outputs;
        delete input.redeem_script_hash;
        delete input.witness_script_hash;

        decoded.inputs[inputIndex] = input;

        input = null;
        inputIndex = null;
        inputKeys = {};
      }

      // Output detected and finished loading its values
      if (!!output) {
        // The scripts of an output must be scripts that the output pays to
        checkOutputScripts({
          redeem: output.redeem_script_buffer,
          script: transactionOutputs[outputIndex].script,
          witness: output.witness_script_buffer,
        });

        delete output.redeem_script_buffer;
        delete output.witness_script_buffer;

        decoded.outputs[outputIndex] = output;

        output = null;
        outputIndex = null;
        outputKeys = {};
      }

      continue;
    }

    // Keys are variable length data
    const keyType = read(keyTypeLength);

    let keyTypeNumber;

    // A key starts with its type, a complete and minimally encoded number
    try {
      keyTypeNumber = readCompactSize({encoded: keyType});
    } catch (err) {
      throw new Error('InvalidPsbtKeyTypeEncoding');
    }

    const keyTypeByteLength = keyTypeNumber.bytes;

    // The key code defines what "type" a key/pair is
    const keyCode = keyType.slice(0, keyTypeByteLength);

    const keyTypeCode = keyCode.toString('hex');

    // Values are variable length data
    const value = read(readCompactVarInt());

    if (isGlobal) {
      // A version has no key data and is a supported 32-bit version number
      if (keyTypeCode === types.global.version) {
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidPsbtVersionTypeKey');
        }

        if (value.length !== versionByteLength) {
          throw new Error('UnexpectedPsbtVersionByteLength');
        }

        if (value.readUInt32LE() !== supportedVersion) {
          throw new Error('UnsupportedPsbtVersion');
        }
      }

      switch (keyType.toString('hex')) {
      case types.global.unsigned_tx:
        if (!!decoded.unsigned_transaction) {
          throw new Error('InvalidGlobalTransactionKeyType');
        }

        let unsignedTx;

        // The unsigned transaction is in the legacy serialization format
        try {
          unsignedTx = legacyTransactionComponents({
            transaction: bufferAsHex(value),
          });
        } catch (err) {
          throw new Error('ExpectedLegacySerializedUnsignedTransaction');
        }

        const {inputs, outputs} = unsignedTx;
        const outpoints = new Set();

        // Every input and output gets its own object, even when left empty
        decoded.inputs = inputs.map(() => ({}));
        decoded.outputs = outputs.map(() => ({}));
        decoded.unsigned_transaction = value.toString('hex');

        terminatorsExpected = inputs.length + outputs.length + countGlobal;
        transactionInputs = inputs;
        transactionOutputs = outputs;

        inputs.forEach(n => {
          if (!!n.script.length) {
            throw new Error('ExpectedEmptyScriptSigs')
          }

          // A transaction can only spend an outpoint once
          if (outpoints.has(`${n.id}:${n.vout}`)) {
            throw new Error('UnexpectedDuplicateInputOutpoint');
          }

          outpoints.add(`${n.id}:${n.vout}`);

          foundInputs.push(n);
        });

        outputs.forEach(n => foundOutputs.push(n));
        break;

      default:
        // The unsigned transaction key has no key data
        if (keyTypeCode === types.global.unsigned_tx) {
          throw new Error('InvalidGlobalTransactionKeyType');
        }

        // Fields reserved for version 2 PSBTs are not allowed in version 0
        if (types.version_2.global.includes(keyTypeCode)) {
          throw new Error('UnexpectedPsbtVersion2GlobalField');
        }

        // An extended public key has a complete key and matching key origin
        if (keyTypeCode === types.global.xpub) {
          checkGlobalXpub({
            value,
            xpub: keyType.subarray(keyTypeByteLength),
          });
        }

        // A proprietary key starts with its identifier and subtype
        if (keyTypeCode === types.global.proprietary) {
          checkProprietaryKey({key: keyType});
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
    } else if (!!foundInputs.length) {
      // Start of a new input?
      if (!input) {
        input = {};
        inputIndex = terminatorsFound - countGlobal;
      }

      if (!!inputKeys[keyType.toString('hex')]) {
        throw new Error('UnexpectedDuplicateInputKey');
      }

      // Keep track of input keys to make sure there's no duplicates
      inputKeys[keyType.toString('hex')] = true;

      // Taproot fields are checked against the output that the input spends
      if (types.taproot_input.includes(keyTypeCode)) {
        hasTaprootFields = true;
      }

      switch (keyTypeCode) {
      case types.input.bip32_derivation:
        const key = keyType.subarray(keyTypeByteLength);

        // The key must be a valid secp256k1 public key
        if (!isPublicKey(key)) {
          throw new Error('InvalidBip32Key');
        }

        const derivation = bip32Derivation({key, derivation: value});

        input.bip32_derivations = input.bip32_derivations || [];

        input.bip32_derivations.push(derivation);
        break;

      case types.input.final_scriptsig:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidFinalScriptSigKey');
        }

        // Check to make sure that the scriptsig is a reasonable script
        if (!asElements(bufferAsHex(value))) {
          throw new Error('InvalidFinalScriptSig');
        }

        input.final_scriptsig = value.toString('hex');
        break;

      case types.input.final_scriptwitness:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidScriptWitnessTypeKey');
        }

        // A witness is an element count then each length-prefixed element
        try {
          const count = compactIntAsNumber({encoded: value});

          const scriptWitness = value.subarray(count.bytes);

          const {elements} = parseWitnessElements({encoded: scriptWitness});

          if (elements.length !== count.number) {
            throw new Error('UnexpectedWitnessElementsCount');
          }

          input.final_scriptwitness = bufferAsHex(scriptWitness);
        } catch (err) {
          throw new Error('InvalidScriptWitness');
        }
        break;

      case types.input.non_witness_utxo:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidNonWitnessUtxoTypeKey');
        }

        const spending = transactionInputs[inputIndex];

        const known = parents.get(spending.id);

        // A previous transaction given for another input was already checked
        const isChecked = !!known && known.transaction.equals(value);

        // The previous transaction is parsed and identified once
        if (!isChecked) {
          let previousTx;

          try {
            previousTx = componentsOfTransaction({
              transaction: bufferAsHex(value),
            });
          } catch (err) {
            throw new Error('ExpectedValidTransactionForNonWitnessUtxo');
          }

          const {id: previousTxId} = transactionId(previousTx);

          // It must be the transaction that the input spends an output of
          if (previousTxId !== spending.id) {
            throw new Error('NonWitnessUtxoDoesNotMatchOutpoint');
          }

          parents.set(spending.id, {
            outputs: previousTx.outputs,
            transaction: value,
          });
        }

        const {outputs: previousOutputs} = parents.get(spending.id);

        // The output being spent must be in the previous transaction
        if (!previousOutputs[spending.vout]) {
          throw new Error('ExpectedSpentOutputInNonWitnessUtxo');
        }

        // Keep the outputs to check the spent output as the input ends
        input.non_witness_utxo_outputs = previousOutputs;

        input.non_witness_utxo = value.toString('hex');
        break;

      case types.input.partial_sig:
        let signature;

        try {
          signature = decodeSignature({signature: value});
        } catch (err) {
          throw new Error('ExpectedValidPartialSignature');
        }

        // A signature ends with a sighash type that Bitcoin defines
        if (!ecdsaSigHashTypes.includes(signature.hash_type)) {
          throw new Error('UnexpectedSigHashTypeForPartialSignature');
        }

        const sigPubKey = keyType.subarray(keyCodeByteLength);

        // Make sure the partial signature public key is a valid pubkey
        if (!isPublicKey(sigPubKey)) {
          throw new Error('InvalidPublicKeyForPartialSig');
        }

        input.partial_sig = input.partial_sig || [];

        input.partial_sig.push({
          hash_type: signature.hash_type,
          public_key: bufferAsHex(sigPubKey),
          signature: signature.signature.toString('hex'),
        });
        break;

      case types.input.redeem_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidRedeemScriptTypeKey');
        }

        // Make sure the redeem script is a reasonable script
        if (!asElements(bufferAsHex(value))) {
          throw new Error('InvalidRedeemScript');
        }

        input.redeem_script = value.toString('hex');
        input.redeem_script_hash = hash160({data: value});
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
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidTapInternalKeyTypeKey');
        }

        if (value.length !== xOnlyPublicKeyByteLength) {
          throw new Error('ExpectedXOnlyPublicKeyForTapInternalKey');
        }

        input.taproot_internal_key = bufferAsHex(value);
        break;

      case types.input.tap_key_sig:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidTapKeySigTypeKey');
        }

        if (!isSchnorrSignature(value)) {
          throw new Error('UnexpectedSizeOfTaprootKeySignature');
        }

        // A trailing sighash byte must be a sighash type Bitcoin allows
        if (!isTapSigHash(value)) {
          throw new Error('UnexpectedSigHashTypeForTaprootKeySignature');
        }

        // The signature sighash is kept apart from the input's sighash type
        input.taproot_key_spend_sig = bufferAsHex(valueAsSchnorrSig(value));
        input.taproot_key_spend_sig_hash_type = valueAsSigHash(value);
        break;

      case types.input.tap_leaf_script:
        const controlBlock = keyType.slice(keyCodeByteLength);

        if (!isControlBlockLength(controlBlock.length)) {
          throw new Error('ExpectedControlBlockForTapLeafScriptInput');
        }

        // The value is the leaf script followed by its leaf version
        if (!value.length) {
          throw new Error('ExpectedLeafVersionForTapLeafScriptInput');
        }

        if (!isLeafVersion({version: versionForLeafScript(value)})) {
          throw new Error('InvalidLeafVersionForTapLeafScriptInput');
        }

        // The control block carries the same leaf version as the script
        if ((controlBlock[0] & taprootLeafVersionMask) !== value.at(-1)) {
          throw new Error('UnexpectedControlBlockLeafVersionForLeafScript');
        }

        input.taproot_control_block = bufferAsHex(controlBlock);
        input.taproot_leaf_script = bufferAsHex(scriptForLeafScript(value));
        input.taproot_leaf_version = versionForLeafScript(value);

        // Every leaf script is kept, including when there are several
        input.taproot_leaf_scripts = input.taproot_leaf_scripts || [];

        input.taproot_leaf_scripts.push({
          control_block: input.taproot_control_block,
          script: input.taproot_leaf_script,
          version: input.taproot_leaf_version,
        });
        break;

      case types.input.tap_merkle_root:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidTapMerkleRootTypeKey');
        }

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

        // A trailing sighash byte must be a sighash type Bitcoin allows
        if (!isTapSigHash(value)) {
          throw new Error('UnexpectedSigHashTypeForTaprootScriptSignature');
        }

        const publicKey = keyType.subarray(keyCodeByteLength, tapScriptSigEnd);
        const leafHash = keyType.subarray(tapScriptSigEnd);

        input.taproot_leaf_hash = bufferAsHex(leafHash);
        input.taproot_leaf_public_key = bufferAsHex(publicKey);
        input.taproot_script_signature = bufferAsHex(valueAsSchnorrSig(value));

        // Every script signature is kept along with its own sighash type
        const scriptSignatures = input.taproot_script_signatures || [];

        scriptSignatures.push({
          hash_type: valueAsSigHash(value),
          leaf_hash: input.taproot_leaf_hash,
          public_key: input.taproot_leaf_public_key,
          signature: input.taproot_script_signature,
        });

        input.taproot_script_signatures = scriptSignatures;
        break;

      case types.input.witness_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidWitnessScriptTypeKey');
        }

        // Make sure that the witness script is a reasonable script
        if (!asElements(bufferAsHex(value))) {
          throw new Error('InvalidWitnessScript');
        }

        input.witness_script = value.toString('hex');
        input.witness_script_hash = sha256(value);
        break;

      case types.input.witness_utxo:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidInputWitnessUtxoTypeKey');
        }

        let pubKeyLen;

        // The tokens are followed by the length of the output script
        try {
          pubKeyLen = compactIntAsNumber({
            encoded: value,
            start: tokensByteLength,
          });
        } catch (err) {
          throw new Error('ExpectedScriptPubLengthForWitnessUtxo');
        }

        const scriptPub = value.subarray(tokensByteLength + pubKeyLen.bytes);

        // The script must be exactly as long as its stated length
        if (scriptPub.length !== pubKeyLen.number) {
          throw new Error('UnexpectedScriptPubLengthForWitnessUtxo');
        }

        const tokens = tokensAsNumber({value});

        input.witness_utxo = {tokens, script_pub: scriptPub.toString('hex')};
        break;

      default:
        // Fields reserved for version 2 PSBTs are not allowed in version 0
        if (types.version_2.input.includes(keyTypeCode)) {
          throw new Error('UnexpectedPsbtVersion2InputField');
        }

        // A hash preimage must hash to the hash in its key
        if (!!types.preimages[keyTypeCode]) {
          checkPreimage({
            hash: keyType.subarray(keyTypeByteLength),
            preimage: value,
            type: keyTypeCode,
          });
        }

        // A proprietary key starts with its identifier and subtype
        if (keyTypeCode === types.input.proprietary) {
          checkProprietaryKey({key: keyType});
        }

        input.unrecognized_attributes = input.unrecognized_attributes || [];

        input.unrecognized_attributes.push({
          type: keyType.toString('hex'),
          value: value.toString('hex'),
        });
        break;
      }
    } else if (!!foundOutputs.length) {
      if (!output) {
        output = {};
        outputIndex = terminatorsFound - countGlobal - decoded.inputs.length;
      }

      // Taproot fields of an output describe a taproot output
      if (types.taproot_output.includes(keyTypeCode)) {
        const {script} = transactionOutputs[outputIndex];

        const {output_key} = taprootOutputKey({script});

        if (!output_key) {
          throw new Error('UnexpectedTaprootFieldForNonTaprootOutput');
        }
      }

      if (!!outputKeys[keyType.toString('hex')]) {
        throw new Error('UnexpectedDuplicateOutputKey');
      }

      // Keep track of the output key to guard against duplicates
      outputKeys[keyType.toString('hex')] = true;

      switch (keyTypeCode) {
      case types.output.bip32_derivation:
        const key = keyType.subarray(keyTypeByteLength);

        // The key must be a valid secp256k1 public key
        if (!isPublicKey(key)) {
          throw new Error('InvalidBip32Key');
        }

        output.bip32_derivation = bip32Derivation({key, derivation: value});

        // Every derivation is kept, including when there are several
        output.bip32_derivations = output.bip32_derivations || [];

        output.bip32_derivations.push(output.bip32_derivation);
        break;

      case types.output.redeem_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputRedeemScriptTypeKey');
        }

        // Make sure that the redeem script is a reasonable script
        if (!asElements(bufferAsHex(value))) {
          throw new Error('InvalidOutputRedeemScript');
        }

        output.redeem_script = value.toString('hex');
        output.redeem_script_buffer = value;
        break;

      case types.output.tap_bip32_derivation:
        output.bip32_derivation = taprootBip32({
          type: bufferAsHex(keyType),
          value: bufferAsHex(value),
        });

        // Every derivation is kept, including when there are several
        output.bip32_derivations = output.bip32_derivations || [];

        output.bip32_derivations.push(output.bip32_derivation);
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
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputTapTreeTypeKey');
        }

        const encoded = bufferAsHex(value);

        output.taproot_script_tree = parseTaprootTree({encoded}).tree;
        break;

      case types.output.witness_script:
        // The key must only contain the 1 byte type.
        if (keyType.length > keyCodeByteLength) {
          throw new Error('InvalidOutputWitnessScriptTypeKey');
        }

        // Make sure that the witness script is a reasonable script
        if (!asElements(bufferAsHex(value))) {
          throw new Error('InvalidOutputWitnessScript');
        }

        output.witness_script = value.toString('hex');
        output.witness_script_buffer = value;
        break;

      default:
        // Fields reserved for version 2 PSBTs are not allowed in version 0
        if (types.version_2.output.includes(keyTypeCode)) {
          throw new Error('UnexpectedPsbtVersion2OutputField');
        }

        // A proprietary key starts with its identifier and subtype
        if (keyTypeCode === types.output.proprietary) {
          checkProprietaryKey({key: keyType});
        }

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

  // The global section must include an unsigned transaction
  if (!decoded.unsigned_transaction) {
    throw new Error('ExpectedUnsignedTransaction');
  }

  if (terminatorsExpected !== terminatorsFound) {
    throw new Error('ExpectedAdditionalOutputs');
  }

  return decoded;
};
