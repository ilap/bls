//// @hidden
//// Tests for basic G2 implementation

use aiken/collection/list
use aiken/primitive/bytearray
use bls/g2_basic as bls

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
