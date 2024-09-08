//// 
//// Golden tests
//// 
//// Test vectors downloaded from [BLS12-381 Github repository](https://github.com/AntelopeIO/bls12-381/blob/6b718d127a2b6095593a85622b4e3f85c3fbbcf6/test/test_vectors.inc#L1)
////

use aiken/collection/list.{at}
use aiken/fuzz.{int_between}
use aiken/primitive/string.{to_bytearray}
use bls/core.{sign, skToPk, verify}
use bls/data/test_vectors as tv

/// Dummy
pub fn golden() {
  True
}

test golden_skToPk(n via int_between(0, 102)) {
  expect Some(pk) = at(tv.pubs(), n)
  expect Some(sk) = at(tv.privs(), n)

  let pkt1 = skToPk(sk)
  pkt1 == pk
}

test golden_sign(n via int_between(0, 102)) {
  expect Some(sk) = at(tv.privs(), n)
  expect Some(msg) = at(tv.msgs(), n)
  expect Some(sig) = at(tv.sigs(), n)

  let sigt1 = sign(sk, to_bytearray(msg))
  sigt1 == sig
}

test golden_verify(n via int_between(0, 102)) {
  expect Some(pk) = at(tv.pubs(), n)
  expect Some(msg) = at(tv.msgs(), n)
  expect Some(sig) = at(tv.sigs(), n)

  verify(pk, to_bytearray(msg), sig)
}
