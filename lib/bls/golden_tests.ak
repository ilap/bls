//// 
//// Golden tests
//// 
//// Test vectors downloaded from [BLS12-381 Github repository](https://github.com/AntelopeIO/bls12-381/blob/6b718d127a2b6095593a85622b4e3f85c3fbbcf6/test/test_vectors.inc#L1)
////

use aiken/fuzz.{int_between}
use aiken/list.{at}
use aiken/string.{to_bytearray}
use bls/bls.{sign, skToPk, verify}
use bls/data/test_vectors as tv

/// Dummy
pub fn golden() {
  True
}

test golden_skToPk(n via int_between(0, 102)) {
  let pk =
    when at(tv.pubs(), n) is {
      Some(a) -> a
      _ -> fail @"Pubkey"
    }
  let sk =
    when at(tv.privs(), n) is {
      Some(a) -> a
      _ -> fail @"Privs"
    }

  let pkt1 = skToPk(sk)
  pkt1 == pk
}

test golden_sign(n via int_between(0, 102)) {
  let sk =
    when at(tv.privs(), n) is {
      Some(a) -> a
      _ -> fail @"Privs"
    }
  let msg =
    when at(tv.msgs(), n) is {
      Some(a) -> to_bytearray(a)
      _ -> fail @"Messages"
    }
  let sig =
    when at(tv.sigs(), n) is {
      Some(a) -> a
      _ -> fail @"Signatures"
    }

  let sigt1 = sign(sk, msg)
  sigt1 == sig
}

test golden_verify(n via int_between(0, 102)) {
  let p =
    when at(tv.pubs(), n) is {
      Some(a) -> a
      _ -> fail @"Pubkey"
    }
  let m =
    when at(tv.msgs(), n) is {
      Some(a) -> to_bytearray(a)
      _ -> fail @"Messages"
    }
  let r =
    when at(tv.sigs(), n) is {
      Some(a) -> a
      _ -> fail @"Signatures"
    }

  verify(p, m, r)
}
