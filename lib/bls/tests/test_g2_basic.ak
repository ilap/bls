//// @hidden
//// Tests for basic G2 implementation

use aiken/collection/list
use aiken/primitive/bytearray
use bls/g2_basic as bls
use bls/g2_pop as pop
use bls/tests/utils

const message = "Message to sign"

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
  !bytearray.is_empty(bls.skToPk(bytearray.from_int_big_endian(1, 32)))
}

test g2_basic_sign_valid() {
  !bytearray.is_empty(bls.sign(bytearray.from_int_big_endian(1, 32), message))
}

test g2_basic_aggregate_valid_single() {
  let sig = bls.sign(bytearray.from_int_big_endian(1, 32), message)
  !bytearray.is_empty(bls.aggregate_signatures([sig]))
}

test g2_basic_verify_success() {
  let pk = bls.skToPk(bytearray.from_int_big_endian(1, 32))
  let sig = bls.sign(bytearray.from_int_big_endian(1, 32), message)

  bls.verify(pk, message, sig)
}

test g2_basic_verify_fail_wrong_pk() {
  let pk = bls.skToPk(bytearray.from_int_big_endian(2, 32))
  let sig = bls.sign(bytearray.from_int_big_endian(1, 32), message)

  !bls.verify(pk, message, sig)
}

test g2_basic_rogue_key_attack() {
  // ------------------------------------------------------------
  // Two honest participants generate normal keys
  // ------------------------------------------------------------
  let sk1 = bytearray.from_int_big_endian(1, 32)
  let sk2 = bytearray.from_int_big_endian(2, 32)

  let pk1 = bls.skToPk(sk1)
  let pk2 = bls.skToPk(sk2)

  // ------------------------------------------------------------
  // Attacker generates their own independent key pair
  // ------------------------------------------------------------
  let sk_fake = bytearray.from_int_big_endian(999, 32)
  let pk_fake = bls.skToPk(sk_fake)

  let pk3 = utils.construct_rogue_key(pk1, pk2, pk_fake)

  // ------------------------------------------------------------
  // Attacker signs the message ALONE
  // ------------------------------------------------------------
  let sig_fake = bls.sign(sk_fake, message)

  // ------------------------------------------------------------
  // Verification succeeds even though honest parties never signed.
  // This demonstrates the classic rogue‑key attack against
  // Basic BLS without PoP or distinct‑message enforcement.
  // ------------------------------------------------------------
  bls.aggregate_verify([pk1, pk2, pk3], [message, message, message], sig_fake)
}

test g2_pop_prevents_rogue_key_attack() {
  let sk1 = bytearray.from_int_big_endian(1, 32)
  let sk2 = bytearray.from_int_big_endian(2, 32)

  let pk1 = pop.skToPk(sk1)
  let pk2 = pop.skToPk(sk2)

  // Honest PoPs
  let pop1 = pop.pop_prove(sk1)
  let pop2 = pop.pop_prove(sk2)

  expect pop.pop_verify(pk1, pop1)
  expect pop.pop_verify(pk2, pop2)

  // Attacker constructs rogue key but CANNOT produce valid PoP
  // because they do not know the corresponding private key.
  let sk_fake = bytearray.from_int_big_endian(999, 32)
  let pk_fake = pop.skToPk(sk_fake)

  // attacker builds rogue key (same method as before)
  let rogue_pk = utils.construct_rogue_key(pk1, pk2, pk_fake)

  // PoP verification fails → registration rejected
  !pop.pop_verify(rogue_pk, pop1)
}
