const {equal} = require('node:assert').strict;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const tinysecp = require('tiny-secp256k1');

const {extractTransaction} = require('./../../');
const {unextractTransaction} = require('./../../');

// Test scenarios
const tests = [
  // Test p2tr
  {
    args: {
      spending: [
        '01000000000101c267c1f8bdc53f69a06cb791ab684d913b9b318511618bee2c56f144ef2f2fd10000000000ffffffff02de91f62901000000160014a5157aec1a4babeeb7f66288597bd10ca26554ab40420f0000000000225120bf5690f1bc5f738cb8e4fced9073e33705a1283870531e282449af45162a6eb8024830450221009c0f9c414ab9bab50f476888e945e6ab668556c2adc056fe016efc7acb3e8cdc02203edd2759d343479ebd42ff10c613fed1f2cc53f3ba7bd9685bbe0ce5306658b2012102ccc5de06aa951bbf9b17bff83c760783c197fff64cb723f1ffc6d47192fd84f700000000',
      ],
      transaction: '02000000000101a82f1922fb7d3de5ec7f7a10639f649f467f86cdd9dd58e6b21875ccb8a417d50100000000ffffffff029e7307000000000016001472924e7842611d799aa663c779fa589cfda04be320a1070000000000225120bf5690f1bc5f738cb8e4fced9073e33705a1283870531e282449af45162a6eb801406f31a87e4997440277c02417dc7b4c8bd64ba571d4f4e271ca3afb43c54590a564c6870511cec4ec4c95ae4de04d8cd7822e94daf89ac17e8da99cd175b7141400000000',
    },
    description: 'A p2tr spend is converted to psbt',
    expected: {
      psbt: '70736274ff01007d0200000001a82f1922fb7d3de5ec7f7a10639f649f467f86cdd9dd58e6b21875ccb8a417d50100000000ffffffff029e7307000000000016001472924e7842611d799aa663c779fa589cfda04be320a1070000000000225120bf5690f1bc5f738cb8e4fced9073e33705a1283870531e282449af45162a6eb8000000000001084201406f31a87e4997440277c02417dc7b4c8bd64ba571d4f4e271ca3afb43c54590a564c6870511cec4ec4c95ae4de04d8cd7822e94daf89ac17e8da99cd175b7141401012b40420f0000000000225120bf5690f1bc5f738cb8e4fced9073e33705a1283870531e282449af45162a6eb8000000',
    },
  },

  // Test p2pkh
  {
    args: {
      spending: [
        '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1802bb010890ee6234173e4a720b2f503253482f627463642fffffffff01807c814a000000001976a914285d3d34c3f32f670bb4453faeb22b31a7a8b51e88ac00000000',
        '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1802bc0108446fcbc213eeb20b0b2f503253482f627463642fffffffff01807c814a000000001976a914285d3d34c3f32f670bb4453faeb22b31a7a8b51e88ac00000000',
      ],
      transaction: '02000000025d41e25e363dcce85afd95251bda8750ce7ebbb494a217f417ecbebd75ae15d6000000006b483045022100cdb3ab6728a59bbd5c2de16ba240badedefc365d0124b8ca4d8a01d77d100fe702206c99adff905dd501856b1506624c5df813cd57f6e39811e49b71dde6135c7c8b0121022adbe9155789877ec30d9b0c75c88c459a0528f9c521b293b36cd44ac2e2326effffffff8e006ee17fc0254c988a37f561307c6820caeacd455881bd8dcd8964b9bd0d0f000000006b4830450221008e1fe9c2c635ffdc0fd2a7f256728f3a0a250f3975ac8c9767821147d07193b80220678fa2c56d421d566078da9d9cde74d752c0a65fb299f2c72a70f1fee0f5a9d00121022adbe9155789877ec30d9b0c75c88c459a0528f9c521b293b36cd44ac2e2326effffffff0240420f0000000000220020e94e96819d685d34aff4dfa56d567eb1fb43e7d0fc8c2cb8fce0c6d4e71ed5ed40420f0000000000220020056538e7b25394e9ac2e0f452ceb5b06ebc648516f69a36335d42a0c446680fc00000000',
    },
    description: 'A pay to public key hash funded tx is converted to psbt',
    expected: {
      psbt: '70736274ff0100b202000000025d41e25e363dcce85afd95251bda8750ce7ebbb494a217f417ecbebd75ae15d60000000000ffffffff8e006ee17fc0254c988a37f561307c6820caeacd455881bd8dcd8964b9bd0d0f0000000000ffffffff0240420f0000000000220020e94e96819d685d34aff4dfa56d567eb1fb43e7d0fc8c2cb8fce0c6d4e71ed5ed40420f0000000000220020056538e7b25394e9ac2e0f452ceb5b06ebc648516f69a36335d42a0c446680fc000000000001076b483045022100cdb3ab6728a59bbd5c2de16ba240badedefc365d0124b8ca4d8a01d77d100fe702206c99adff905dd501856b1506624c5df813cd57f6e39811e49b71dde6135c7c8b0121022adbe9155789877ec30d9b0c75c88c459a0528f9c521b293b36cd44ac2e2326e01006d01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1802bb010890ee6234173e4a720b2f503253482f627463642fffffffff01807c814a000000001976a914285d3d34c3f32f670bb4453faeb22b31a7a8b51e88ac000000000001076b4830450221008e1fe9c2c635ffdc0fd2a7f256728f3a0a250f3975ac8c9767821147d07193b80220678fa2c56d421d566078da9d9cde74d752c0a65fb299f2c72a70f1fee0f5a9d00121022adbe9155789877ec30d9b0c75c88c459a0528f9c521b293b36cd44ac2e2326e01006d01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1802bc0108446fcbc213eeb20b0b2f503253482f627463642fffffffff01807c814a000000001976a914285d3d34c3f32f670bb4453faeb22b31a7a8b51e88ac00000000000000',
    },
  },

  // Test p2sh and p2wsh
  {
    args: {
      spending: [
        '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000',
        '0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000',
      ],
      transaction: '0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000',
    },
    description: 'Spend p2sh and p2wsh outputs',
    expected: {
      psbt: '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000000107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae0100f80200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f796500000001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887000000',
    },
  },

  // Test p2wpkh
  {
    args: {
      spending: [
        '010000000001018962c86967d717090ae678eb0fb02e1b7cc036afad57ddf3e7c17ab025e29ee0010000001716001482c3d3a8b0317dc15f29f1d8cddb0d70e542b07cffffffff02c4166900000000002200200df13f481d8504547e9a768e04021d4633580e4e2ea30947bdb10696b73d49acfcc9731100000000160014ca6ee81f8110eac35eae23accb6d676284f9027d02483045022100dc00bebabdfb18633dabe7ddc3d2c1889608c7ce071178b9a6db7c2ab989655102207542fba17c272d5bf0145847d20559c45e9fd09a67e6a6c935eeba95e53e4c15012102e91f67abc81c5419bef5db1e76404117729052fcc325a91189fd417debbefc1e00000000',
      ],
      transaction: '01000000000101f0ea93013c35acbf94695db3bf806c0de68f5309d63f415f1f74548e37db277f0100000000ffffffff020000000100000000220020fdef2b21b827959dcaf3d31f8f0f859cd81ec5d335614ed4e338cdf8ce9d6fcb3692711000000000160014736fb0c4deb3259b49a3ecfc56e18dbdb6a2a757024730440220171fac3e95f5f2c98ae8c5115d71cf283683a68b23c418429e142f7dd478cc410220166d5f9e8a5a88ad154827072c38053155ce821e6f772ab0eb7c114a40512b6c0121026aeb31fdbb5c3a4511611dca0bdb5545b1828edc40344af2d8c8e26190313a7100000000',
    },
    description: 'Spend p2wpkh output',
    expected: {
      psbt: '70736274ff01007d0100000001f0ea93013c35acbf94695db3bf806c0de68f5309d63f415f1f74548e37db277f0100000000ffffffff020000000100000000220020fdef2b21b827959dcaf3d31f8f0f859cd81ec5d335614ed4e338cdf8ce9d6fcb3692711000000000160014736fb0c4deb3259b49a3ecfc56e18dbdb6a2a757000000000001086b024730440220171fac3e95f5f2c98ae8c5115d71cf283683a68b23c418429e142f7dd478cc410220166d5f9e8a5a88ad154827072c38053155ce821e6f772ab0eb7c114a40512b6c0121026aeb31fdbb5c3a4511611dca0bdb5545b1828edc40344af2d8c8e26190313a710100fd0201010000000001018962c86967d717090ae678eb0fb02e1b7cc036afad57ddf3e7c17ab025e29ee0010000001716001482c3d3a8b0317dc15f29f1d8cddb0d70e542b07cffffffff02c4166900000000002200200df13f481d8504547e9a768e04021d4633580e4e2ea30947bdb10696b73d49acfcc9731100000000160014ca6ee81f8110eac35eae23accb6d676284f9027d02483045022100dc00bebabdfb18633dabe7ddc3d2c1889608c7ce071178b9a6db7c2ab989655102207542fba17c272d5bf0145847d20559c45e9fd09a67e6a6c935eeba95e53e4c15012102e91f67abc81c5419bef5db1e76404117729052fcc325a91189fd417debbefc1e0000000001011ffcc9731100000000160014ca6ee81f8110eac35eae23accb6d676284f9027d000000',
    },
  },

  // Test spend n2wpkh
  {
    args: {
      spending: [
        '02000000000101a848e71523adf7411f4f769d4ed03380c7f5349887000085daa9fa923447b45c0100000017160014cb339ccd577dfc1b4c45c207885f3b5cdc2d284efeffffff02421c4b340000000017a9148bd7d7a1ff61daa038b23a5c0df21a621e64140587801a0600000000001976a914f46a6e6b7c3f6430e7ddc7d5758dd7f56399152b88ac02483045022100daad3a603c18a4ceb00edbed523f75e00b114e4dbf8d9d59b74cfa24735fc826022074984a5e43f9ee0610f81f7bc85f9af97540b0fe7d0728b40ac6255a8e1b81f5012103870669b3834b35c9db6320ad020d9b2c261dbd00c77b43acbe0dc7acaf15d3cc27870900',
      ],
      transaction: '020000000001015f0b472537749768102d5f9951b435838adde676edc8d29a4226a503618a47210000000017160014fad65e863edbc1294c336d0d4c55d4766d7d220efeffffff02b28924340000000017a914c4937d3406a8134af77e4ad3546e94c21c76e10987a0252600000000001976a9146e617ca48592c10574fb0021954d2130bd9e914b88ac02483045022100c8d103ce59ea4ec690c835ffd6b619a649808d14b365f5aec481697971f134f0022042744350a509b9da65213f4425e922d588c99fadfa950b9dc92b0e7d085077ef012103be9420bb4ace4387d76ac52e101223a47b5cbdb07987d905de9d6cd60e3368db28870900',
    },
    description: 'Spend np2wpkh output',
    expected: {
      psbt: '70736274ff01007502000000015f0b472537749768102d5f9951b435838adde676edc8d29a4226a503618a47210000000000feffffff02b28924340000000017a914c4937d3406a8134af77e4ad3546e94c21c76e10987a0252600000000001976a9146e617ca48592c10574fb0021954d2130bd9e914b88ac2887090000010717160014fad65e863edbc1294c336d0d4c55d4766d7d220e01086c02483045022100c8d103ce59ea4ec690c835ffd6b619a649808d14b365f5aec481697971f134f0022042744350a509b9da65213f4425e922d588c99fadfa950b9dc92b0e7d085077ef012103be9420bb4ace4387d76ac52e101223a47b5cbdb07987d905de9d6cd60e3368db0100fa02000000000101a848e71523adf7411f4f769d4ed03380c7f5349887000085daa9fa923447b45c0100000017160014cb339ccd577dfc1b4c45c207885f3b5cdc2d284efeffffff02421c4b340000000017a9148bd7d7a1ff61daa038b23a5c0df21a621e64140587801a0600000000001976a914f46a6e6b7c3f6430e7ddc7d5758dd7f56399152b88ac02483045022100daad3a603c18a4ceb00edbed523f75e00b114e4dbf8d9d59b74cfa24735fc826022074984a5e43f9ee0610f81f7bc85f9af97540b0fe7d0728b40ac6255a8e1b81f5012103870669b3834b35c9db6320ad020d9b2c261dbd00c77b43acbe0dc7acaf15d3cc27870900010120421c4b340000000017a9148bd7d7a1ff61daa038b23a5c0df21a621e64140587000000',
    },
  },

  // Test spend non segwit into segwit
  {
    args: {
      spending: [
        '0100000001b2a8808ee7684c76a3111f7afb275eca2d0f212bf70540ec4a42534f296a86a4000000006a4730440220408623359ccd7a1673583c00aa699a9b3180752b345e63a464ca833a10f6ac7a02200284cbf05688dcd9562de9cf41ecab1c9743506c6aac7e03e84105ef2ed2fec1012103dc214c6bdcd29f6455911a9897a9465a69d1c676e213c126f71046ad0c4fd3d7ffffffff0118ee052a0100000017a91456467fa47d5f868adc1f1013da9107940aaff0be8700000000',
      ],
      transaction: '0100000000010164d6de62524ba8079edfafef169be3d988197dad8314c35babde5fcc89b1b07b00000000171600144da8437135fe9f1af8d5669b6396c117ac953334ffffffff0340420f000000000022002065d2375a5d4b138eabbea149019d3bcc880a4282944be41181fa6c1399764a2cd23ee72901000000160014166916179c2dcb8aad18c77e251864b16f1e2f9240420f00000000002200207ac485a6bff112d4370ec15e059c57837c478ec71f372bdaeb86f1cc44bfee400247304402200a6c7efaa3135907949d51de024de6ee68a87aa8758c6c8819a09d6e74e1c03c02200344e7539188dfdee78efbf7e0facd0a9f5f895a84a550c3bc38770ece186afe01210347fd4a797e9bc13307c23701f9f37c5cde871ebc5be9f279cae00cc7902fbecc00000000',
    },
    description: 'Upgrading to segwit',
    expected: {
      psbt: '70736274ff0100a8010000000164d6de62524ba8079edfafef169be3d988197dad8314c35babde5fcc89b1b07b0000000000ffffffff0340420f000000000022002065d2375a5d4b138eabbea149019d3bcc880a4282944be41181fa6c1399764a2cd23ee72901000000160014166916179c2dcb8aad18c77e251864b16f1e2f9240420f00000000002200207ac485a6bff112d4370ec15e059c57837c478ec71f372bdaeb86f1cc44bfee4000000000000107171600144da8437135fe9f1af8d5669b6396c117ac95333401086b0247304402200a6c7efaa3135907949d51de024de6ee68a87aa8758c6c8819a09d6e74e1c03c02200344e7539188dfdee78efbf7e0facd0a9f5f895a84a550c3bc38770ece186afe01210347fd4a797e9bc13307c23701f9f37c5cde871ebc5be9f279cae00cc7902fbecc0100bd0100000001b2a8808ee7684c76a3111f7afb275eca2d0f212bf70540ec4a42534f296a86a4000000006a4730440220408623359ccd7a1673583c00aa699a9b3180752b345e63a464ca833a10f6ac7a02200284cbf05688dcd9562de9cf41ecab1c9743506c6aac7e03e84105ef2ed2fec1012103dc214c6bdcd29f6455911a9897a9465a69d1c676e213c126f71046ad0c4fd3d7ffffffff0118ee052a0100000017a91456467fa47d5f868adc1f1013da9107940aaff0be870000000001012018ee052a0100000017a91456467fa47d5f868adc1f1013da9107940aaff0be8700000000',
    },
  },

  // Test spend multisig
  {
    args: {
      spending: [
        '010000000001012a5e9943f8df7abff835ec6003c9a544e8404521d2e0210d89fd40fda9d766ab00000000171600144da8437135fe9f1af8d5669b6396c117ac953334ffffffff0340420f00000000002200208b12e1377c3a9ed179468724d79ce9004affeaf79b93fde3f25bf2824140dbba40420f0000000000220020cdf6fca2a8197858161d96bda10c4a2b4aa8e1625271a9b57a8d29fb26b85559d23ee72901000000160014166916179c2dcb8aad18c77e251864b16f1e2f9202483045022100abc005d724aa39beaf17471175ad756e89d8b49067d00a64697d5cd2158be9b702206397f0a3dd9bc74359c8bb1a99fa6df91df011f0359b5b91396b1fd5fbbfc42201210347fd4a797e9bc13307c23701f9f37c5cde871ebc5be9f279cae00cc7902fbecc00000000',
      ],
      transaction: '02000000000101148b3f5a75420de37e0e786de7f6999eb98a394c42c440378b2698202af531300000000000ffffffff01e61e0f0000000000160014349bf7b65ce65c98e1f916acd94e45aa5196f40d04004730440220373fe857a531eba5e87bf145fdbbcdcf14ae5c162116d58b2e3685d2a445ae340220739d7b2992eaeadbfcfb8d083504a0f499d85ea7c0353e1a35e6e826d793711b0147304402203218e05ee634a23142e4287eb8b4fbd3034c017686dc7f0a88ccd9b890b4a35f022018cb48e418536244b4af79b069a9d9d6caa9de4c7e6a8aff94b6fd38032fd92501475221024512f87fd6d35fdcb5dfd59bc03e5495802bd802530704f2df28a143ed5dcb3f2102ae77c0512ff8d7caff3c527a666917d9e4f502b50937a1f9b96cecf5869c91d252ae00000000',
    },
    description: 'Spend multisig',
    expected: {
      psbt: '70736274ff0100520200000001148b3f5a75420de37e0e786de7f6999eb98a394c42c440378b2698202af531300000000000ffffffff01e61e0f0000000000160014349bf7b65ce65c98e1f916acd94e45aa5196f40d00000000000108da04004730440220373fe857a531eba5e87bf145fdbbcdcf14ae5c162116d58b2e3685d2a445ae340220739d7b2992eaeadbfcfb8d083504a0f499d85ea7c0353e1a35e6e826d793711b0147304402203218e05ee634a23142e4287eb8b4fbd3034c017686dc7f0a88ccd9b890b4a35f022018cb48e418536244b4af79b069a9d9d6caa9de4c7e6a8aff94b6fd38032fd92501475221024512f87fd6d35fdcb5dfd59bc03e5495802bd802530704f2df28a143ed5dcb3f2102ae77c0512ff8d7caff3c527a666917d9e4f502b50937a1f9b96cecf5869c91d252ae0100fd2d01010000000001012a5e9943f8df7abff835ec6003c9a544e8404521d2e0210d89fd40fda9d766ab00000000171600144da8437135fe9f1af8d5669b6396c117ac953334ffffffff0340420f00000000002200208b12e1377c3a9ed179468724d79ce9004affeaf79b93fde3f25bf2824140dbba40420f0000000000220020cdf6fca2a8197858161d96bda10c4a2b4aa8e1625271a9b57a8d29fb26b85559d23ee72901000000160014166916179c2dcb8aad18c77e251864b16f1e2f9202483045022100abc005d724aa39beaf17471175ad756e89d8b49067d00a64697d5cd2158be9b702206397f0a3dd9bc74359c8bb1a99fa6df91df011f0359b5b91396b1fd5fbbfc42201210347fd4a797e9bc13307c23701f9f37c5cde871ebc5be9f279cae00cc7902fbecc0000000001012b40420f00000000002200208b12e1377c3a9ed179468724d79ce9004affeaf79b93fde3f25bf2824140dbba0000',
    },
  },
];

// Run the tests
tests.forEach(({args, err, expected, description}) => {
  return test(description, async () => {
    const ecp = (await import('ecpair')).ECPairFactory(tinysecp);

    args.ecp = ecp;

    const got = unextractTransaction(args);

    equal(got.psbt, expected.psbt, 'PSBT is formed as expected');

    const extracted = extractTransaction({ecp, psbt: got.psbt});

    equal(extracted.transaction, args.transaction, 'TX can be extracted');

    return;
  });
});
