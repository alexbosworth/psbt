# PSBTs

PSBTs are a format for communicating and collaboratively working with
transactions.

The format is defined in BIP-0174:
[https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)

## Methods

### combinePsbts

Combine multiple PSBTs

Values that describe a spend, such as UTXOs, scripts, key origins, and
sighash types, must match across PSBTs. For other values that differ, such
as signatures and final scripts, the earliest PSBT's value is used.

Signatures must use the sighash type of their input when it has one. A 64
byte taproot signature uses the default sighash type.

    {
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

When a timelock is set, inputs without a sequence use a sequence that lets
the timelock take effect

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

    @throws
    <Error>

    @returns
    {
      psbt: <Partially Signed Bitcoin Transaction Hex Encoded String>
    }

### decodePsbt

Decode a BIP 174 encoded PSBT

Public keys are returned exactly as they are encoded in the PSBT. The PSBT
version, global extended public keys, proprietary fields, and hash preimages
are checked and returned as unrecognized attributes.

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

### encodePsbt

Encode a Partially Signed Bitcoin Transaction

Every key starts with a complete, minimally encoded type number, and a key
can only be used once within a section. A separator ends a section. The
pairs must encode a valid PSBT.

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

### extendPsbt

Extend a PSBT with additional input fields

Existing values are kept, and added values replace existing values that
have the same key.

Signatures must use the sighash type of their input when it has one. A 64
byte taproot signature uses the default sighash type.

A final script witness is given as it is encoded in a PSBT: the count of
witness elements, then each length prefixed element.

    {
      inputs: [{
        [bip32_derivations]: [{
          fingerprint: <Public Key Fingerprint Hex String>
          [leaf_hashes]: [<Taproot Leaf Hash Hex String>]
          [path]: <BIP 32 Child / Hardened Child / Index Derivation Path String>
          public_key: <Public Key Hex String>
        }]
        [final_scriptsig]: <Final ScriptSig Hex String>
        [final_scriptwitness]: <Witness Elements With Count Hex String>
        [non_witness_utxo]: <Non-Witness Hex Encoded Transaction String>
        [partial_sig]: [{
          hash_type: <Signature Hash Type Number>
          public_key: <Public Key Hex String>
          signature: <ECDSA Signature Hex String>
        }]
        [redeem_script]: <Hex Encoded Redeem Script String>
        [sighash_type]: <Sighash Type Number>
        [taproot_key_spend_sig]: <Taproot Key Spend Signature Hex String>
        [witness_script]: <Witness Script Hex String>
        [witness_utxo]: {
          script_pub: <UTXO ScriptPub Hex String>
          tokens: <Tokens Number>
        }
      }]
      psbt: <BIP 174 Encoded PSBT String>
    }

    @throws
    <Error>

    @returns
    {
      psbt: <Extended PSBT Hex String>
    }

### extractTransaction

Extract a transaction from a finalized PSBT

Every input needs a final scriptSig or a final script witness, either of
which can be empty. A transaction needs inputs and outputs to be extracted.

The transaction is serialized with witnesses when an input has a final
script witness with at least one element, even if the element is empty.

    {
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

### signPsbt

Update a PSBT with signatures

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

### transactionAsPsbt

Convert a signed transaction to a signed PSBT

Inputs can spend P2PKH, P2WPKH, and nested P2WPKH outputs, and P2SH, P2WSH,
nested P2WSH, and bare outputs with a script that pays to a public key, to
a public key hash, or to a multisig where every key signs. Other spends are
rejected, as is a conversion that would not finalize to the same
transaction.

The PSBT keeps the exact locktime and input sequences of the transaction.

    {
      spending: [<Spending Transaction Hex String>]
      transaction: <Hex Encoded Transaction String>
    }

    @throws
    <Error>

    @returns
    {
      psbt: <Signed PSBT String>
    }

### unextractTransaction

Convert a raw transaction into a finalized PSBT ready for extraction

An input that spends a legacy output needs the full previous transaction
that it spends from. An input that spends a witness output, including a
P2SH output spent with a push of the witness program that it hashes, can
instead have a UTXO reference to the output that it spends. A UTXO
reference given along with the previous transaction must describe the same
output.

    {
      spending: [<Spending Transaction Hex String>]
      transaction: <Hex Encoded Transaction String>
      [utxos]: [{
        script_pub: <Output Script Hex String>
        tokens: <Output Tokens Number>
        vin: <Input Index Number>
      }]
    }

    @throws
    <Error>

    @returns
    {
      psbt: <Finalized PSBT Hex String>
    }

### updatePsbt

Update a PSBT

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
