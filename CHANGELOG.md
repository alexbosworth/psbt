# Versions

## 7.0.1

- Methods no longer take an `ecp` object
- `signPsbt` and `finalizePsbt` handle P2PKH, P2PK, bare multisig, P2WPKH,
    taproot key spends, and P2SH, P2WSH and nested scripts that pay to a key,
    a key hash or a multisig, using the input's sighash type
- `finalizePsbt` checks signatures, puts multisig signatures in key order,
    and with `is_partial` finalizes only the inputs that are ready
- Updating, signing, combining and extending keep what is already in a
    PSBT, such as signatures, sighash types, taproot and unknown fields
- `updatePsbt` matches scripts and key paths to the output each input
    spends, adds them to outputs too, and adds the full funding transaction
    of version 0 witness inputs
- `decodePsbt` returns more taproot fields and output key origins
- `signPsbt` accepts the `signet` and `testnet4` networks

### Breaking Changes

- PSBTs are checked strictly by every method: malformed encodings, UTXOs
    and scripts that don't match the output being spent, duplicate inputs,
    undefined sighash types and version 2 fields are rejected
- Signatures must use their input's sighash type, including taproot
    signatures, where 64 bytes means the default type
- `decodePsbt` returns public keys exactly as encoded, and `sighash_type`
    only from the input's sighash field
- `combinePsbts` keeps the earliest PSBT's value when values conflict, and
    rejects PSBTs that disagree on UTXOs, scripts, key origins or sighash types
- `finalizePsbt` rejects inputs without a UTXO, unsupported scripts and
    inputs without enough valid signatures, instead of making invalid scripts.
    A taproot key spend that signs every input needs every input's UTXO
- `signPsbt` only signs with keys the script checks, needs the full previous
    transaction for legacy inputs and a UTXO for witness inputs, and won't
    sign witness inputs with uncompressed keys
- `transactionAsPsbt` needs the spending transaction of every input and only
    converts supported spends that finalize to the same transaction
- Arguments are validated, for example `createPsbt` amounts, ids and
    scripts, and `encodePsbt` must produce a valid PSBT
- Some error names changed, for example `ExpectedSeparator` is now
    `ExpectedKeyAndValueForPsbtPair`

## 6.0.4

- Require node.js 22 or higher

### Breaking Changes

- Support for chains other than Bitcoin is removed. The `network` value for
    `signPsbt` must now be `bitcoin`, `regtest`, or `testnet`. Bitcoin Cash,
    Litecoin, and other alternative chain networks are no longer recognized
    and fork id sighash signing is no longer performed.

## 5.0.0

- Require node.js 20 or higher

## 4.0.0

- Require node.js 18 or higher

## 3.0.0

- Require node.js 16 or higher

## 2.7.2

- Add support for node.js 18+

## 2.7.0

- `extendPsbt`: Add support for `taproot_key_spend_sig`
- `extendPsbt`: Fix `partial_sig` argument to take an array of partial sigs

## 2.6.0

- `unextractTransaction`: Add support for witness-only `utxos` references

## 2.5.0

- `combinePsbts`: Add support for combining p2tr key spend input PSBTs
- `updatePsbt`: Add support for `taproot_inputs` when using key spend signature

## 2.4.0

- `unextractTransaction`: Add method to reconstitute a finalized psbt from a tx

## 2.3.0

- `decodePsbt`: Add support for incomplete inputs and output sets
- `extendPsbt`: Add `final_scriptsig`, `final_scriptwitness`,
    `non_witness_utxo`, `partial_sig`, `redeem_script`, `witness_script` to
    supported input types.

## 2.2.0

- `decodePsbt`: Fix incorrect decoding of bip32 derivation paths
- `extendPsbt`: Add method to extend a PSBT with specific input metadata

## 2.1.0

- `decodePsbt`: Add support for decoding BIP 371 Taproot fields

## 2.0.1

- Update bitcoinjs-lib dependency

### Breaking Changes

- `combinePsbts`, `decodePsbt`, `extractTransaction`, `finalizePsbt`,
    `signPsbt`, `transactionAsPsbt`, and `updatePsbt` now require `ecp` object

## 1.1.11

- `updatePsbt`: Add support for bip32 derivation paths on p2wpkh spends

## 1.1.10

- `signPsbt`: add discovery of pay to witness public keys to sign

## 1.1.6

- `transactionAsPsbt`: add method to convert a signed tx to a signed PSBT
