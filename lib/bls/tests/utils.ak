use aiken/builtin

/// Rogue‑key construction
///
/// The attacker creates a *malicious public key* that cancels the
/// honest participants' keys inside the aggregated public key:
///
///     pk3 = pk_fake - (pk1 + pk2)
///
/// After aggregation:
///
///     pk1 + pk2 + pk3 = pk_fake
///
/// This makes the verifier believe all three parties signed,
/// while in reality only the attacker signs.
pub fn construct_rogue_key(
  pk1: ByteArray,
  pk2: ByteArray,
  pk_fake: ByteArray,
) -> ByteArray {
  let p1 = builtin.bls12_381_g1_uncompress(pk1)
  let p2 = builtin.bls12_381_g1_uncompress(pk2)
  let pf = builtin.bls12_381_g1_uncompress(pk_fake)

  let sum12 = builtin.bls12_381_g1_add(p1, p2)
  let neg_sum12 = builtin.bls12_381_g1_neg(sum12)

  let rogue_point = builtin.bls12_381_g1_add(pf, neg_sum12)
  builtin.bls12_381_g1_compress(rogue_point)
}
