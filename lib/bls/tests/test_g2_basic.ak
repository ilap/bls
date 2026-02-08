//// @hidden
//// Tests for basic G2 implementation

use aiken/collection/list
use aiken/primitive/bytearray
use bls/g2_basic as bls
use bls/tests/utils

test g2_basic_aggregate_verify_success() {
  // 0 is invalid sk. We start from 1 to ensure valid keys and signatures.
  let sksi = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

  let sks = list.map(sksi, fn(i) { bytearray.from_int_big_endian(i, 32) })

  let msgs = sks

  // 48-byte length pks. 
  let pks = list.map(sks, bls.skToPk)

  let sigs = list.map2(sks, msgs, fn(sk, msg) { bls.sign(sk, msg) })

  let agg = bls.aggregate_signatures(sigs)

  expect bls.aggregate_verify(pks, msgs, agg)
}

test g2_basic_aggregate_verify_duplicate_messages() {
  let sksi = [1, 2, 3]
  let sks = list.map(sksi, fn(i) { bytearray.from_int_big_endian(i, 32) })

  let msgs = [#"3432", #"3639", #"3432"]

  let pks = list.map(sks, bls.skToPk)

  let sigs = list.map2(sks, msgs, fn(sk, msg) { bls.sign(sk, msg) })

  let agg = bls.aggregate_signatures(sigs)

  expect bls.aggregate_verify(pks, msgs, agg)
}

test g2_basic_aggregate_distinct_verify_duplicate_messages() {
  let sksi = [1, 2, 3]
  let sks = list.map(sksi, fn(i) { bytearray.from_int_big_endian(i, 32) })

  let msgs = [#"3432", #"3639", #"3432"]

  let pks = list.map(sks, bls.skToPk)

  let sigs = list.map2(sks, msgs, fn(sk, msg) { bls.sign(sk, msg) })

  let agg = bls.aggregate_signatures(sigs)

  expect False = bls.aggregate_distinct_verify(pks, msgs, agg)
}

test g2_basic_sk_to_pk_valid() {
  !bytearray.is_empty(bls.skToPk(utils.sk1))
}

test g2_basic_sign_valid() {
  !bytearray.is_empty(bls.sign(utils.sk1, utils.message))
}

test g2_basic_aggregate_valid_single() {
  let sig = bls.sign(utils.sk1, utils.message)
  !bytearray.is_empty(bls.aggregate_signatures([sig]))
}

test g2_basic_verify_success() {
  let pk = bls.skToPk(utils.sk1)
  let sig = bls.sign(utils.sk1, utils.message)

  bls.verify(pk, utils.message, sig)
}

test g2_basic_verify_fail_wrong_pk() {
  let pk = bls.skToPk(utils.sk2)
  let sig = bls.sign(utils.sk1, utils.message)

  !bls.verify(pk, utils.message, sig)
}

/// This test returns True in vulnerable Basic BLS implementations without:
///  - Proof‑of‑Possession (PoP), or
///  - distinct‑message enforcement.
///
/// This attack works even if pk1 and pk2 never signed anything.
/// The attacker mathematically constructs a key that absorbs them into their own signature.
///
/// This is why:
///   - Basic BLS requires **PoP**, OR
///   - **distinct messages**, OR
///   - **Augmented mode**.
test g2_basic_rogue_key_attack() {
  // Classic rogue-key attack: forged key verifies even though honest parties never signed.
  // Check lib/bls/utils.ak for the rogue key construction method.
  bls.aggregate_verify(
    [utils.pk1, utils.pk2, utils.rogue_pk],
    [utils.message, utils.message, utils.message],
    utils.sig_fake,
  )
}

test g2_basic_rogue_key_attack_blocked_by_distinct_messages() {
  // Attack fails: each key has a distinct message, so single attacker signature cannot verify.
  // Check lib/bls/utils.ak for the rogue key construction method.
  !bls.aggregate_verify(
    [utils.pk1, utils.pk2, utils.rogue_pk],
    [utils.message, utils.other_message, utils.another_message],
    utils.sig_fake,
  )
}

test g2_basic_rogue_key_attack_blocked_enforced_by_aggregate_distinct_verify() {
  // Distinct-message check enforces uniqueness: attack cannot succeed.
  // Check lib/bls/utils.ak for the rogue key construction method.
  !bls.aggregate_distinct_verify(
    [utils.pk1, utils.pk2, utils.rogue_pk],
    [utils.message, utils.other_message, utils.another_message],
    utils.sig_fake,
  )
}

test g2_basic_rogue_key_attack_fails_without_distinct_messages_with_aggregate_distinct_verify() {
  // Duplicate messages detected: distinct-message verification rejects aggregation.
  // Check lib/bls/utils.ak for the rogue key construction method.
  !bls.aggregate_distinct_verify(
    [utils.pk1, utils.pk2, utils.rogue_pk],
    [utils.message, utils.message, utils.message],
    utils.sig_fake,
  )
}
