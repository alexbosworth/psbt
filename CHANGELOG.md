# Versions

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
