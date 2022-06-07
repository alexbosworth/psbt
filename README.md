# PSBTs

PSBTs are a format for communicating and collaboratively working with
transactions.

The format is defined in BIP-0174:
[https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)

## Methods

An ECPair object is required for some methods:

```node
const tinysecp = require('tiny-secp256k1');

const ECPair = await import('ecpair')

const ecp = ECPair.ECPairFactory(tinysecp);
```

### combinePsbts

Combine multiple PSBTs

    {
      ecp: <ECPair Object>
      psbts: [<BIP 174 Encoded PSBT Hex String>]
    }

    @throws
    <Combine PSBT Error>

    @returns
    {
      psbt: <BIP 174 Encoded PSBT Hex String>
    }

### createPsbt

Create a PSBT

    {
      outputs: [{
        script: <Output ScriptPub Hex String>
        tokens: <Sending Tokens Number>
      }]
      utxos: [{
        id: <Transaction Id Hex String>
        [sequence]: <Sequence Number>
        vout: <Output Index Number>
      }]
      [timelock]: <Set Lock Time on Transaction To Number>
      [version]: <Transaction Version Number>
    }

    @returns
    {
      psbt: <Partially Signed Bitcoin Transaction Hex Encoded String>
    }

### decodePsbt

Decode a BIP 174 encoded PSBT

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

### encodePsbt

Encode a Partially Signed Bitcoin Transaction

    {
      pairs: [{
        [separator]: <Is Separator Bool>
        [type]: <Type Buffer Object>
        [value]: <Value Buffer Object>
      }]
    }

    @throws
    <Failed To Encode Error>

    @returns
    {
      psbt: <Hex Encoded Partially Signed Bitcoin Transaction String>
    }

### extractTransaction

Extract a transaction from a finalized PSBT

    {
      ecp: <ECPair Object>
      psbt: <BIP 174 Encoded PSBT Hex String>
    }

    @throws
    <Extract Transaction Error>

    @returns
    {
      transaction: <Hex Serialized Transaction String>
    }

### finalizePsbt

Finalize the inputs of a PSBT

    {
      ecp: <ECPair Object>
      psbt: <BIP 174 Encoded PSBT Hex String>
    }

    @throws
    <Finalize PSBT Error>

    @returns
    {
      psbt: <BIP 174 Encoded PSBT Hex String>
    }

### signPsbt

Update a PSBT with signatures

    {
      ecp: <ECPair Object>
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

### transactionAsPsbt

Convert a signed transaction to a signed PSBT

Note: not all signed transactions can be converted to a signed PSBT. For
example, a preimage cannot be represented in a standard PSBT.

    {
      ecp: <ECPair Object>
      spending: [<Spending Transaction Hex String>]
      transaction: <Hex Encoded Transaction String>
    }

    @throws
    <Error>

    @returns
    {
      psbt: <Signed PSBT String>
    }

### updatePsbt

Update a PSBT

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
        vin: <Signature Input Index Number>
        hash_type: <Signature Hash Type Number>
        public_key: <BIP 32 Public Key String>
        signature: <Signature Hex String>
      }]
      [taproot_inputs]: [{
        vin: <Input Index Number>
        [key_spend_sig]: <Taproot Key Spend Signature Hex String>
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
