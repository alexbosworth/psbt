# Versions

## 2.7.1

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
