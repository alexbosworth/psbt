const {test} = require('tap');

const {decodePsbt} = require('./../../');
const {finalizePsbt} = require('./../../');

// Test scenarios
const tests = {
   a_finalizer_creates_a_fully_signed_psbt: {
    args: {
      psbt: '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01220202dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887220203089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f012202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000',
    },
    msg: 'An input finalizer must create a finalized PSBT',
    result: {
      psbt: '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000',
    },
  },

  finalize_additional_elements_p2sh: {
    args: {
      psbt: '70736274ff01005502000000015b82c2d6b66d4c5d3b316aac88b026d5fb412e60fbf0d950901957c2912c5f260000000000000000000100f2052a010000001976a914b97e80b0443e337ab44953118f7cf39d6b3af24888acc9010000000100bd020000000196ada02170fa9c97f0840cfc2f212b2bbd883c4ff625b88199ef6530e07fc185000000006a473044022037bcace270a91c6c27aade188c084d55288bbd424ca52e6aa7d0073a652bfe4202206273ee275271ef076715cf6bfa7c8503d90cbe1af2740d03e7a5f1d34164de4501210244fd8dd0196b986bb129403e7a24f0c016ab02b827e3dacb8262265b050dcf6fffffffff0100f2052a0100000017a914104ec32142689cc07d261c08e4f28c0d39720f01870000000022020244fd8dd0196b986bb129403e7a24f0c016ab02b827e3dacb8262265b050dcf6f473044022048917d7867ef1b028f4976e1e61a51f0d129254176259a759f102bef00afd74702203316bca21854115c31125634e4ec44d6536c6b7e73a5bbbe5d8a32a7070a25da0101030401000000010470a820313b69ce7c7083831eee437ba9325dd865d94844d35f748f96a2e21ced7d7d3287632103f1d45f238ff0382b8731e8c6ab07ceed4b1b852034059ac386b2bc022e1cd4b46702c901b175210244fd8dd0196b986bb129403e7a24f0c016ab02b827e3dacb8262265b050dcf6f68ac05090100000001000000',
    },
    msg: 'When finalizing a p2sh psbt, tx is finalized',
    result: {
      psbt: '70736274ff01005502000000015b82c2d6b66d4c5d3b316aac88b026d5fb412e60fbf0d950901957c2912c5f260000000000000000000100f2052a010000001976a914b97e80b0443e337ab44953118f7cf39d6b3af24888acc9010000000100bd020000000196ada02170fa9c97f0840cfc2f212b2bbd883c4ff625b88199ef6530e07fc185000000006a473044022037bcace270a91c6c27aade188c084d55288bbd424ca52e6aa7d0073a652bfe4202206273ee275271ef076715cf6bfa7c8503d90cbe1af2740d03e7a5f1d34164de4501210244fd8dd0196b986bb129403e7a24f0c016ab02b827e3dacb8262265b050dcf6fffffffff0100f2052a0100000017a914104ec32142689cc07d261c08e4f28c0d39720f0187000000000107ba473044022048917d7867ef1b028f4976e1e61a51f0d129254176259a759f102bef00afd74702203316bca21854115c31125634e4ec44d6536c6b7e73a5bbbe5d8a32a7070a25da014c70a820313b69ce7c7083831eee437ba9325dd865d94844d35f748f96a2e21ced7d7d3287632103f1d45f238ff0382b8731e8c6ab07ceed4b1b852034059ac386b2bc022e1cd4b46702c901b175210244fd8dd0196b986bb129403e7a24f0c016ab02b827e3dacb8262265b050dcf6f68ac0000',
    },
  },

  finalize_additional_elements_p2sh_p2wsh: {
    args: {
      psbt: '70736274ff0100550200000001ed0a1ba8226a329c31622ab9b48fd7a10346281ce76eafe10df68df5a03615590000000000000000000100f2052a010000001976a914ce1fd7c23be24cab701c6422e4950498251a7be788acc9010000000100bd0200000001ef626e7003bb29f97952ba636aa629f7f4903355ff5788adc70eadb63bcbd69f000000006a4730440220064183880b8339dbe3b5a893937f6383e48d6aa76dcbd08921ea0475ba1d5dbb0220187a82e50552153ba3dc53bc8cbac0ea814726ca92698268e015a6409362d64d012103b47963914016d223703a048b5c0e8d667b177b9ef264f7fb49445587526c480fffffffff0100f2052a0100000017a9146065f2ed03e3988c4e52d521ff255fea4fffa1148700000000220203b47963914016d223703a048b5c0e8d667b177b9ef264f7fb49445587526c480f47304402207158388c19d83b58ae090d8e03434ed1d03d0f83986fb49d24f576aefc3a82660220159bb38400e49dd562bbb4b79482e7f963e9fd78b5c7329a2ed65ddf2f90d65a01010304010000000104220020bce297ea506237bf38a66d5a2d2d091e505d2fada0933e03df0019635bbfcf0d01056876a820c099ecdd8375ae8bb70a1ec538a96de324d9595a6c40fcaa17ce4134358f8d338763752103aeb38d95211f19bc2dafcd4fa6ca587b2d03740584e9621bc58621b6238eac396702c901b17576a914ce1fd7c23be24cab701c6422e4950498251a7be78868ac0509010000002103b47963914016d223703a048b5c0e8d667b177b9ef264f7fb49445587526c480f0000',
    },
    msg: 'When finalizing a p2sh p2wsh psbt, tx is finalized',
    result: {
      psbt: '70736274ff0100550200000001ed0a1ba8226a329c31622ab9b48fd7a10346281ce76eafe10df68df5a03615590000000000000000000100f2052a010000001976a914ce1fd7c23be24cab701c6422e4950498251a7be788acc9010000000100bd0200000001ef626e7003bb29f97952ba636aa629f7f4903355ff5788adc70eadb63bcbd69f000000006a4730440220064183880b8339dbe3b5a893937f6383e48d6aa76dcbd08921ea0475ba1d5dbb0220187a82e50552153ba3dc53bc8cbac0ea814726ca92698268e015a6409362d64d012103b47963914016d223703a048b5c0e8d667b177b9ef264f7fb49445587526c480fffffffff0100f2052a0100000017a9146065f2ed03e3988c4e52d521ff255fea4fffa1148700000000010723220020bce297ea506237bf38a66d5a2d2d091e505d2fada0933e03df0019635bbfcf0d0108b30247304402207158388c19d83b58ae090d8e03434ed1d03d0f83986fb49d24f576aefc3a82660220159bb38400e49dd562bbb4b79482e7f963e9fd78b5c7329a2ed65ddf2f90d65a014c6876a820c099ecdd8375ae8bb70a1ec538a96de324d9595a6c40fcaa17ce4134358f8d338763752103aeb38d95211f19bc2dafcd4fa6ca587b2d03740584e9621bc58621b6238eac396702c901b17576a914ce1fd7c23be24cab701c6422e4950498251a7be78868ac0000',
    },
  },

  finalize_additional_elements_p2wsh: {
    args: {
      psbt: '70736274ff0100550200000001a6029c0cc05d57510cf156549a8e03df433f2d004f0b34f48676c277ba8d4e540000000000000000000100f2052a010000001976a914f514b2e3fcdc9b0c0ea4336c93a490e70d62d34388acc9010000000100c90200000001b251e5dda512ed06adf36d51b32a8cfeed26792cab4c8b62873227528301ea47000000006b483045022100c4e0e3f46f401d4a94f6227a6d2f641bf009e71c14441bfad0209a5b670ae45302206db25c0bbb0b442ab77864d56f9a8fcc7dc77b506e8eca4501d509eee9c79caa012102e9853ef895d8d9d7b28c2008cf0fb43a70ac5f48dae2992556619c79329f2e27ffffffff0100f2052a010000002200207d8ae1ce304d3ab5641b93c9feb27e9c93f6c06341c50a86069b4e697e27902c00000000220202e9853ef895d8d9d7b28c2008cf0fb43a70ac5f48dae2992556619c79329f2e27483045022100be32a703b1fe46e2fb515c5f224d8914c289d7279a07530ec0892430952efbff02200144f48e55053a8dd46834c4530188e294fcd1b83c29a0dbf66f6c6b9f038c740101030401000000010570a820ed3809a0cd5cb3f55affd444c1249fd4c21387475ada5ddcefa2e4485038ab5787632102a1dab16c678a1610af03ee6beba27674e94a60cf05d95ba842ba0e4cdfa6c3a36702c901b1752102e9853ef895d8d9d7b28c2008cf0fb43a70ac5f48dae2992556619c79329f2e2768ac05090100000001000000',
    },
    msg: 'When finalizing a p2wsh psbt, tx is finalized',
    result: {
      psbt: '70736274ff0100550200000001a6029c0cc05d57510cf156549a8e03df433f2d004f0b34f48676c277ba8d4e540000000000000000000100f2052a010000001976a914f514b2e3fcdc9b0c0ea4336c93a490e70d62d34388acc9010000000100c90200000001b251e5dda512ed06adf36d51b32a8cfeed26792cab4c8b62873227528301ea47000000006b483045022100c4e0e3f46f401d4a94f6227a6d2f641bf009e71c14441bfad0209a5b670ae45302206db25c0bbb0b442ab77864d56f9a8fcc7dc77b506e8eca4501d509eee9c79caa012102e9853ef895d8d9d7b28c2008cf0fb43a70ac5f48dae2992556619c79329f2e27ffffffff0100f2052a010000002200207d8ae1ce304d3ab5641b93c9feb27e9c93f6c06341c50a86069b4e697e27902c000000000108bc02483045022100be32a703b1fe46e2fb515c5f224d8914c289d7279a07530ec0892430952efbff02200144f48e55053a8dd46834c4530188e294fcd1b83c29a0dbf66f6c6b9f038c74014c70a820ed3809a0cd5cb3f55affd444c1249fd4c21387475ada5ddcefa2e4485038ab5787632102a1dab16c678a1610af03ee6beba27674e94a60cf05d95ba842ba0e4cdfa6c3a36702c901b1752102e9853ef895d8d9d7b28c2008cf0fb43a70ac5f48dae2992556619c79329f2e2768ac0000',
    },
  },
};

// Run the tests
Object.keys(tests).map(t => tests[t]).forEach(({args, err, msg, result}) => {
  return test(msg, ({end, equal}) => {
    const expected = decodePsbt({psbt: result.psbt});
    const {psbt} = finalizePsbt(args);

    equal(psbt, result.psbt);

    const updated = decodePsbt({psbt});

    equal(updated.pairs.length, expected.pairs.length, 'Map size is equal');

    expected.pairs.forEach((n, i) => {
      const got = updated.pairs[i];

      equal(got.type.toString('hex'), n.type.toString('hex'), 'Type match');
      equal(got.value.toString('hex'), n.value.toString('hex'), 'Value match');

      return;
    });

    return end();
  });
});
