const decodePsbt = require('./decode_psbt');
const encodePsbt = require('./encode_psbt');
const {finalizeInputPairs} = require('./../spends');
const {legacyTransactionComponents} = require('./../transactions');
const psbtSections = require('./psbt_sections');
const {spentOutputs} = require('./../spends');
const {taprootSharedHashes} = require('./../sighash');
const {transactionParts} = require('./../sighash');
const {witnessSharedHashes} = require('./../sighash');

/** Finalize the inputs of a PSBT

  Inputs are finalized for the output that they spend, so they need a UTXO.
  The output must pay to a public key, a public key hash, or a multisig,
  directly or through a redeem or witness script, or be a taproot output with
  a key spend signature.

  Signatures of the keys that a script pays to are checked against the
  transaction and the outputs that they spend, and only valid signatures are
  used. ECDSA signatures need a low s value. A taproot key spend signature
  that signs every input needs the output that each input spends.

  A P2SH redeem script can be at most 520 bytes, the most that a scriptSig
  can push. Witness scripts are not limited this way.

  Final inputs keep their UTXO and the fields not used for signing, such as
  unknown and proprietary fields.

  When finalizing is partial, inputs that cannot be finalized, such as inputs
  that are not signed yet, are left as they are instead of stopping the PSBT
  from being finalized.

  {
    [is_partial]: <Finalize Only the Inputs That Can Be Finalized Bool>
    psbt: <BIP 174 Encoded PSBT Hex String>
  }

  @throws
  <Finalize PSBT Error>

  @returns
  {
    psbt: <BIP 174 Encoded PSBT Hex String>
  }
*/
module.exports = ({is_partial, psbt}) => {
  const decoded = decodePsbt({psbt});
  const pairs = [];

  const {sections} = psbtSections({psbt});

  // The pairs of each section are the starting point of the finalized PSBT
  const [globalPairs, ...maps] = sections;

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

  globalPairs.forEach(pair => pairs.push(pair));

  // End of global type values
  pairs.push({separator: true});

  transaction.inputs.forEach((txIn, vin) => {
    let section = maps[vin];

    // Each input is finalized for the output that it spends
    try {
      const finalized = finalizeInputPairs({
        hashes,
        parts,
        vin,
        pairs: maps[vin],
        spent: spent[vin],
        taproot_hashes: taprootHashes,
      });

      section = finalized.pairs;
    } catch (err) {
      // Inputs that cannot be finalized are left as they are when partial
      if (!is_partial) {
        throw err;
      }
    }

    section.forEach(pair => pairs.push(pair));

    // Input pairs termination
    return pairs.push({separator: true});
  });

  // The output pairs are kept as they are
  maps.slice(transaction.inputs.length).forEach(section => {
    section.forEach(pair => pairs.push(pair));

    // Output pairs termination
    return pairs.push({separator: true});
  });

  // The finalized PSBT must be a valid PSBT
  const encoded = encodePsbt({pairs});

  return {psbt: encoded.psbt};
};
