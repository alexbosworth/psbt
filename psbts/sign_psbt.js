const {decodeWif} = require('@alexbosworth/blockchain');
const {pointFromScalar} = require('tiny-secp256k1');
const {sign} = require('tiny-secp256k1');

const decodePsbt = require('./decode_psbt');
const {defaultSigHashType} = require('./constants');
const {ecdsaSigHashTypes} = require('./constants');
const {encodeSignature} = require('./../signatures');
const {hash160} = require('./../spends');
const {inputSignatureHash} = require('./../sighash');
const {inputSpend} = require('./../spends');
const {legacyTransactionComponents} = require('./../transactions');
const networks = require('./networks');
const {scriptSigningKeys} = require('./../spends');
const {sigHashOutputTypeMask} = require('./constants');
const {sigHashSingle} = require('./constants');
const {spentOutputs} = require('./../spends');
const {taprootKeySpendSignature} = require('./../spends');
const {taprootOutputKey} = require('./../utxos');
const {taprootSharedHashes} = require('./../sighash');
const {taprootSigningKey} = require('./../spends');
const {taprootTweakedKey} = require('./../signatures');
const {transactionParts} = require('./../sighash');
const updatePsbt = require('./update_psbt');
const {witnessSharedHashes} = require('./../sighash');

const bufferAsHex = buffer => buffer.toString('hex');
const {isArray} = Array;
const isSingle = n => (n & sigHashOutputTypeMask) === sigHashSingle;
const signHash = (hash, key) => Buffer.from(sign(hash, key.private_key));
const xOnlyOf = publicKey => publicKey.subarray(1, 33);

/** Update a PSBT with signatures

  Inputs are signed by the signing keys that their scripts pay to. A script
  must pay to a public key, to a public key hash, or to a multisig of public
  keys. Inputs with other scripts, finalized inputs, and keys that already
  signed an input are skipped.

  A taproot input gets a key spend signature from the key of its output, or
  from its internal key tweaked with the merkle root of its script tree. A
  signing key is also tried as the internal key of an output without a script
  tree. Taproot inputs without a sighash type are signed with the default
  sighash type, and taproot inputs with a key spend signature are skipped.

  Version 0 witness inputs are only signed with compressed public keys.

  Legacy inputs need their full previous transaction and witness inputs need a
  UTXO to be signed. A taproot signature that signs every input needs the
  UTXO of every input.

  The network is bitcoin, regtest, signet, testnet, or testnet4. An
  unrecognized network name is taken to be the bitcoin network.

  {
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
  const keys = new Map();
  const signatures = [];
  const taprootKeys = new Map();
  const taprootSignatures = [];
  const tweakedKeys = new Map();

  if (!isArray(args.signing_keys)) {
    throw new Error('ExpectedSigningKeysToSignPsbt');
  }

  // Signing keys are decoded for the network, or bitcoin when it is unknown
  const network = networks[args.network] || networks.bitcoin;

  // Index the signing keys by their public keys and their public key hashes
  args.signing_keys.forEach(wif => {
    const wifKey = decodeWif({network, wif});

    const point = pointFromScalar(wifKey.private_key, wifKey.is_compressed);

    const key = {
      private_key: wifKey.private_key,
      public_key: Buffer.from(point),
    };

    keys.set(bufferAsHex(key.public_key), key);
    keys.set(bufferAsHex(hash160({data: key.public_key})), key);

    // A taproot key is the x coordinate of a public key
    taprootKeys.set(bufferAsHex(xOnlyOf(key.public_key)), key);

    return;
  });

  const decoded = decodePsbt({psbt: args.psbt});

  // The unsigned transaction is parsed once for all of the inputs
  const transaction = legacyTransactionComponents({
    transaction: decoded.unsigned_transaction,
  });

  // The signed parts of the transaction are serialized once for all inputs
  const parts = transactionParts({transaction});

  // The hashes that witness signature hashes share are calculated once
  const hashes = witnessSharedHashes({parts});

  // The outputs that inputs spend, parsing each previous transaction once
  const {spent} = spentOutputs({transaction, inputs: decoded.inputs});

  // The hashes that taproot signature hashes share are calculated once
  const taprootHashes = taprootSharedHashes({parts, spent});

  // The output keys of the taproot outputs that inputs spend
  const outputKeys = spent.map(({script}) => taprootOutputKey({script}));

  // Signing keys are tweaked once as internal keys when inputs spend taproot
  if (!!outputKeys.find(n => !!n.output_key)) {
    taprootKeys.forEach(key => {
      const tweaked = taprootTweakedKey({private_key: key.private_key});

      return tweakedKeys.set(tweaked.output_key, tweaked);
    });
  }

  decoded.inputs.forEach((input, vin) => {
    const {output_key} = outputKeys[vin];

    // A finalized input is complete and is not signed again
    if (input.final_scriptsig !== undefined) {
      return;
    }

    if (input.final_scriptwitness !== undefined) {
      return;
    }

    // A taproot input is signed with a key spend signature for its output key
    if (!!output_key) {
      // Exit early when the input already has a key spend signature
      if (input.taproot_key_spend_sig !== undefined) {
        return;
      }

      const {private_key} = taprootSigningKey({
        input,
        output_key,
        keys: taprootKeys,
        tweaked: tweakedKeys,
      });

      // Exit early when none of the signing keys sign for the output key
      if (!private_key) {
        return;
      }

      const {signature} = taprootKeySpendSignature({
        parts,
        private_key,
        vin,
        hashes: taprootHashes,
        sighash_type: input.sighash_type,
        spent: spent[vin],
      });

      return taprootSignatures.push({vin, key_spend_sig: signature});
    }

    const spend = inputSpend({input, spent: spent[vin]});

    // Exit early when the input is not a kind of input that can be signed
    if (!spend.script) {
      return;
    }

    const inScript = scriptSigningKeys({
      keys,
      is_witness: spend.is_witness,
      script: spend.script,
    });

    // Keys that already signed the input keep their existing signatures
    const signingKeys = inScript.keys.filter(key => {
      const publicKey = bufferAsHex(key.public_key);

      return !(input.partial_sig || []).find(n => n.public_key === publicKey);
    });

    if (!signingKeys.length) {
      return;
    }

    // A legacy input's spent output is only verified by its full transaction
    if (!spend.is_witness && !input.non_witness_utxo) {
      throw new Error('ExpectedNonWitnessUtxoToSignLegacyInput');
    }

    // A witness signature commits to the tokens of the output being spent
    if (!!spend.is_witness && spend.tokens === undefined) {
      throw new Error('ExpectedUtxoToSignWitnessInput');
    }

    const hasSigHash = input.sighash_type !== undefined;

    // The signature hash type is chosen once, to hash and to encode with
    const sighash = hasSigHash ? input.sighash_type : defaultSigHashType;

    if (!ecdsaSigHashTypes.includes(sighash)) {
      throw new Error('UnsupportedSigHashTypeToSign');
    }

    // Without an output at its index, a legacy input would sign the number 1
    // for one output, a signature that other transactions could use too
    if (!spend.is_witness && isSingle(sighash) && !transaction.outputs[vin]) {
      throw new Error('ExpectedOutputForInputSigningWithSigHashSingle');
    }

    // The hash to sign for the input is calculated once for all of its keys
    const {hash} = inputSignatureHash({
      hashes,
      parts,
      sighash,
      vin,
      is_witness: spend.is_witness,
      script: spend.script,
      tokens: spend.tokens,
    });

    signingKeys.forEach(key => {
      const signature = encodeSignature({
        flag: sighash,
        signature: bufferAsHex(signHash(hash, key)),
      });

      return signatures.push({
        vin,
        hash_type: sighash,
        public_key: bufferAsHex(key.public_key),
        signature: bufferAsHex(signature),
      });
    });

    return;
  });

  return updatePsbt({
    signatures,
    psbt: args.psbt,
    taproot_inputs: taprootSignatures,
  });
};
