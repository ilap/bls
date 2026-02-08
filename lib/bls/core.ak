//// @hidden
//// This module implements the core operations for BLS12-381 signatures.
////
//// The module provides functions for verifying an aggregate BLS signature for multiple public keys and messages.
//// The verification procedure follows the fast aggregate signature verification method described in [this Ethereum Research post](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407).
////
//// The module assumes that the public keys and messages are provided as byte arrays, and it uses the [aiken/prelude/builtin](https://aiken-lang.github.io/prelude/aiken/builtin.html) module for the underlying cryptographic operations.

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_add, bls12_381_g1_compress,
  bls12_381_g1_scalar_mul, bls12_381_g1_uncompress, bls12_381_g2_add,
  bls12_381_g2_compress, bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul,
  bls12_381_g2_uncompress, bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/collection/list.{foldl, length}
use bls/constants.{
  dst_aug_G2, dst_basic_G2, dst_pop_G2, point_base_G1, point_zero_G1,
  point_zero_G2,
}
use bls/types.{Aug, Basic, BlsMode, Pop}
use bls/utils.{foldl2}

// Internal DST selection
fn select_dst(mode: BlsMode) -> ByteArray {
  when mode is {
    Basic -> dst_basic_G2
    Aug -> dst_aug_G2
    Pop -> dst_pop_G2
  }
}

/// This function performs a pairing operation on elements represented by two byte arrays.
/// It uncompresses the byte arrays to their respective elements and then calls the group_pairing function.
pub fn pairing(g1: ByteArray, g2: ByteArray) {
  let g1_element = bls12_381_g1_uncompress(g1)
  let g2_element = bls12_381_g2_uncompress(g2)

  group_pairing(g1_element, g2_element)
}

// This function performs the pairing operation using the Miller loop algorithm on two elements,
// one from G1 and one from G2.
pub fn group_pairing(g1: G1Element, g2: G2Element) {
  bls12_381_miller_loop(g1, g2)
}

/// Generates a BLS12_381 signature for a given message using the private key.
/// The function hashes the message to a point on the G2 curve, converts the private key to a scalar,
/// and multiplies the scalar with the point. The resulting point is then compressed to obtain the signature.
///
/// Parameters:
/// * `sk`: ByteArray - The private key of the user.
/// * `message`: ByteArray - The message to be signed.
///
/// Returns:
/// G2Element - The compressed BLS12_381 signature for the given message.
pub fn internal_sign(
  sk: ByteArray,
  message: ByteArray,
  mode: BlsMode,
) -> ByteArray {
  let s = bytearray_to_integer(True, sk)

  bls12_381_g2_hash_to_group(message, select_dst(mode))
    |> bls12_381_g2_scalar_mul(s, _)
    |> bls12_381_g2_compress
}

/// Converts a secret key (sk) to a corresponding public key (PK) using the BLS12-381 elliptic curve.
/// Computes the public key by multiplying the secret key with the generator point.
///
/// Parameters:
/// * `sk`: ByteArray - The secret key of the user.
///
/// Returns:
/// ByteArray - The compressed public key corresponding to the secret key.
pub fn internal_skToPk(sk: ByteArray) -> ByteArray {
  let s = bytearray_to_integer(True, sk)
  //  The private key should not be zero, as it would lead to an invalid public key 
  // (the point at infinity).
  expect s != 0
  bls12_381_g1_scalar_mul(s, point_base_G1)
    |> bls12_381_g1_compress
}

/// Verifies a BLS12_381 signature for a given message and public key.
/// The function converts the signature to a point, hashes the message to a point on the G1 curve,
/// and computes two pairing values to check if they are equal, determining the signature's validity.
///
/// Parameters:
/// * `pk`: ByteArray - The public key of the signer.
/// * `message`: ByteArray - The message to be verified.
/// * `signature`: ByteArray - The BLS12_381 signature to be verified.
///
/// Returns:
/// bool - `true` if the signature is valid, `false` otherwise.
pub fn internal_verify(
  pk: ByteArray,
  message: ByteArray,
  signature: ByteArray,
  mode: BlsMode,
) -> Bool {
  let p = bls12_381_g1_uncompress(pk)

  // 1. Convert signature to a point.
  let s = bls12_381_g2_uncompress(signature)

  // 2. Hash the message to a point.
  let q = bls12_381_g2_hash_to_group(message, select_dst(mode))

  // Check if the pairing of the public key and hashed message is equal to the pairing of the generator and signature.
  let c1 = group_pairing(p, q)
  let c2 = group_pairing(point_base_G1, s)
  bls12_381_final_verify(c1, c2)
}

/// Aggregates multiple BLS signatures into a single signature.
/// Uses the foldl function to aggregate the signatures by uncompressing and adding them,
/// and then compresses the resulting aggregated point.
///
/// Parameters:
/// * `signatures`: List<ByteArray> - A list of signatures to be aggregated.
///
/// Returns:
/// ByteArray - The compressed aggregated signature.
pub fn internal_aggregate_signatures(signatures: List<ByteArray>) -> ByteArray {
  aggregate_g2(signatures)
}

/// Aggregates multiple BLS public keys into a single public key.
/// Uses the **`foldl`** function to iteratively uncompress and add the public keys,
/// and then compresses the resulting aggregated public key.
///
/// Arguments:
/// * publickeys: List<ByteArray> - A list of BLS public keys to be aggregated.
///
/// Returns:
/// ByteArray - The compressed aggregated BLS public key.
pub fn internal_aggregate_publickeys(publickeys: List<ByteArray>) -> ByteArray {
  aggregate_g1(publickeys)
}

pub fn aggregate_g1(elems: List<ByteArray>) -> ByteArray {
  if length(elems) <= 0 {
    fail @"G1: Cannot aggregate an empty list."
  } else {
    foldl(
      elems,
      point_zero_G1,
      fn(elem, sum) { bls12_381_g1_add(bls12_381_g1_uncompress(elem), sum) },
    )
      |> bls12_381_g1_compress
  }
}

pub fn aggregate_g2(elems: List<ByteArray>) -> ByteArray {
  if length(elems) <= 0 {
    fail @"G2: Cannot aggregate an empty list."
  } else {
    foldl(
      elems,
      point_zero_G2,
      fn(elem, sum) { bls12_381_g2_add(bls12_381_g2_uncompress(elem), sum) },
    )
      |> bls12_381_g2_compress
  }
}

/// Function to verify an aggregate BLS signature for multiple public keys and messages
///
/// Parameters:
/// * `pks`: List<ByteArray> - a list of public keys
/// * `messages`: List<ByteArray> - a list of messages
/// * `signature`: ByteArray - the aggregate BLS signature to be verified
///
/// Returns:
/// Bool - `true` if the signature is valid, `false` otherwise
///
/// Precondition:
/// * The length of `pks` and `messages` is the same and at least 1, otherwise the function will fail.
///
pub fn internal_aggregate_verify(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  signature: ByteArray,
  mode: BlsMode,
) -> Bool {
  expect [pk, ..xs] = pks
  expect [msg, ..ys] = messages

  let p = bls12_381_g1_uncompress(pk)
  let q = bls12_381_g2_hash_to_group(msg, select_dst(mode))
  let ml = group_pairing(p, q)
  let c1 =
    foldl2(
      xs,
      ys,
      ml,
      fn(pk, message, miller_loop) {
        let p = bls12_381_g1_uncompress(pk)
        let q = bls12_381_g2_hash_to_group(message, select_dst(mode))
        let pq = group_pairing(p, q)
        bls12_381_mul_miller_loop_result(pq, miller_loop)
      },
    )

  let s = bls12_381_g2_uncompress(signature)
  let c2 = group_pairing(point_base_G1, s)

  bls12_381_final_verify(c1, c2)
}
