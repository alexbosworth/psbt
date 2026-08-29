/** Supported networks and their ECPair network constants

  {
    [network]: {
      messagePrefix: <Signed Message Prefix String>
      bech32: <Bech32 Human Readable Part String>
      bip32: {
        public: <BIP32 Public Key Version Number>
        private: <BIP32 Private Key Version Number>
      }
      pubKeyHash: <Pay to Public Key Hash Address Version Number>
      scriptHash: <Pay to Script Hash Address Version Number>
      wif: <WIF Private Key Version Number>
    }
  }
*/
module.exports = {
  bitcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {public: 0x0488b21e, private: 0x0488ade4},
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
  },
  regtest: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bcrt',
    bip32: {public: 0x043587cf, private: 0x04358394},
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  },
  testnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {public: 0x043587cf, private: 0x04358394},
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  },
};
