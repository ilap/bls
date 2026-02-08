use bls/core
use bls/types.{Basic}

// Tests

const sk1 = #"6284b61a07c6bd3e632beb6294dfc780ad04489c8c31b73b0aef73608f3d1231"

const pk1 =
  #"82cbde4e4fc6a56b6f84f2ceabb191ed7d4402835f8caa1e166554e7d7a925fe2cab59f113b78c91a4b37001d2a9c75f"

const sg1 =
  #"b558aab6dd33d777973a19fb34c3a1c636315a039a0e9ea7da4f78fe5d4470a0b4ec3d2b3324b81e5e759875c224c8ec0e1ce698faa40426165f799cb358d965b8e8dc82ee01f702008e68a0309a8261bb5e348f349521b26eed6961c22de869"

// const sk2 = #"4a03db9a98c2e54003dbd674a0834d27b9bc6ea5d51a3ad87dae25196fd7f7b3"
const pk2 =
  #"81e6046450d77df1af198c6c3d440d1fea3af4e9ea27e261b48f57e353ecebf3641e84058a7874ab1c1523bc332d3891"

const sg2 =
  #"ac9dcb405d0ed0a6943ef79eec13bfb458c627c0dec66161277f7bccacf8b96ccdb25d6f9842ab256198e7589b50603511978d3c68b41646b7985585ad519910ea064d9bb39a0b5fd3964676563063f8d6836d7a9bb72d86a682c8ef333735ec"

// const sk3 = #"5d59e156ca0924b190d8a5d835a1fc152c297c26da2f3ca9c223ea7486c62c9e"
const rogue_pk =
  #"8e153a4d9757d148df8a82eca0d8c294789968c7c7a8b7d375690b27ed51d43076178d8769290878fbdb8c0e7a997c4f"

const sg3 =
  #"a811f30a85b3544af7988ff05e910d4bb562971df4955647d39e42682313097383011c65f85f74fb297e72c3ca41d01703db9375af025d2091337fdd24b81c52e1591e74cfa44176a3a06e0087a42fb27b6a3d82e12180b978f21881d1ed3455"

const sg12 =
  #"8115fd8e5a24ad8fdab93efad7abc98ee14ea09943249cb048ecdd8295cf7df80c41ca5629904f55dce2efba50af96c6147139f75bbb9b7173ebfd9c92566d890beab4a1dc7fd5b2d8774d9806d596f507834cdb77bedafd9e57833facfde4a1"

const sg123 =
  #"a736fab8cc9c7c323e063defabbad493bad0c95b6c780a24a6fd53d3a773f9bf59272bb7148006538ce37766bd68667513286a0e50da5e4b331a50fb5e617b059fad0e76de709686076c6177a805f53d4e83fb9cdeaa5fa4eea3a5c021100dd7"

// const sg12_3 = #"a736fab8cc9c7c323e063defabbad493bad0c95b6c780a24a6fd53d3a773f9bf59272bb7148006538ce37766bd68667513286a0e50da5e4b331a50fb5e617b059fad0e76de709686076c6177a805f53d4e83fb9cdeaa5fa4eea3a5c021100dd7"
const pk12 =
  #"a390b4ff941bd64d5b09234bffa29fb1ee018c89571e6e8920d23b37c7f43ab00e3cbc2db84c3a749f45d37d32227f38"

// const pk13 = #"b1354209c656b817f7582a1e8f38510ce05a02a4b28caf93b667b417349eebfabb9aa0dd59a1ddceace92b7fa4bc77b4"
const pk123 =
  #"8683036a550330afd097ed52f0536a07ee61c7a7621704bfce3097dada49feff523a71976ec6148f30427749839ba33c"

const msg1 = #"000001"

const msg2 = #"000002"

const msg3 = #"000003"

test core_sign() {
  let signature = core.internal_sign(sk1, msg1, Basic)
  signature == sg1
}

test core_skToPk() {
  let result = core.internal_skToPk(sk1)
  result == pk1
}

test core_verify() {
  core.internal_verify(pk1, msg1, sg1, Basic)
}

test core_aggregate_verify_1() {
  core.internal_aggregate_verify([pk1], [msg1], sg1, Basic)
}

test core_aggregate_verify_2() {
  core.internal_aggregate_verify([pk1, pk2], [msg1, msg2], sg12, Basic)
}

test core_aggregate_verify_3() {
  core.internal_aggregate_verify(
    [pk1, pk2, rogue_pk],
    [msg1, msg2, msg3],
    sg123,
    Basic,
  )
}

test core_aggregate_signatures() {
  let agg = core.internal_aggregate_signatures([sg1, sg2])
  agg == sg12
}

test core_aggregate_shuffled_signatures_6x() {
  sg123 == core.internal_aggregate_signatures([sg1, sg2, sg3]) && sg123 == core.internal_aggregate_signatures(
    [sg1, sg3, sg2],
  ) && sg123 == core.internal_aggregate_signatures([sg2, sg3, sg1]) && sg123 == core.internal_aggregate_signatures(
    [sg2, sg1, sg3],
  ) && sg123 == core.internal_aggregate_signatures([sg3, sg1, sg2]) && sg123 == core.internal_aggregate_signatures(
    [sg3, sg2, sg1],
  )
}

test core_aggregate_shuffled_signatures_2_6x() {
  sg123 == core.internal_aggregate_signatures([sg12, sg3]) && sg123 == core.internal_aggregate_signatures(
    [sg3, sg12],
  )
}

test core_aggregate_publickeys() {
  let agg = core.internal_aggregate_publickeys([pk1, pk2])
  agg == pk12
}

test core_aggregate_shuffled_publickes_6x() {
  pk123 == core.internal_aggregate_publickeys([pk1, pk2, rogue_pk]) && pk123 == core.internal_aggregate_publickeys(
    [pk1, rogue_pk, pk2],
  ) && pk123 == core.internal_aggregate_publickeys([pk2, rogue_pk, pk1]) && pk123 == core.internal_aggregate_publickeys(
    [pk2, pk1, rogue_pk],
  ) && pk123 == core.internal_aggregate_publickeys([rogue_pk, pk1, pk2]) && pk123 == core.internal_aggregate_publickeys(
    [rogue_pk, pk2, pk1],
  )
}

test core_aggregate_shuffled_publickes_2_6x() {
  pk123 == core.internal_aggregate_publickeys([pk12, rogue_pk]) && pk123 == core.internal_aggregate_publickeys(
    [rogue_pk, pk12],
  )
}
