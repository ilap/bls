//// This module implements operations for BLS12-381 signatures.
////
//// The module provides functions for verifying an aggregate BLS signature for multiple public keys and messages.
//// The verification procedure follows the fast aggregate signature verification method described in [this Ethereum Research post](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407).
////
//// The module assumes that the public keys and messages are provided as byte arrays, and it uses the [aiken/builtin](https://github.com/aiken-lang/aiken-stdlib/tree/main/builtin) and [bls/constants](https://github.com/aiken-lang/aiken-stdlib/tree/main/bls/constants) modules for the underlying cryptographic operations.

use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_compress, bls12_381_g1_scalar_mul,
  bls12_381_g1_uncompress, bls12_381_g2_add, bls12_381_g2_compress,
  bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul, bls12_381_g2_uncompress,
  bls12_381_miller_loop, bls12_381_mul_miller_loop_result, bytearray_to_integer,
}
use aiken/list.{foldl, head, length, tail, zip}
use bls/constants.{dst_basic_G2, point_base_G1, point_zero_G2}

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
pub fn sign(sk: ByteArray, message: ByteArray) -> ByteArray {
  let s = bytearray_to_integer(True, sk)

  bls12_381_g2_hash_to_group(message, dst_basic_G2)
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
pub fn skToPk(sk: ByteArray) -> ByteArray {
  let s = bytearray_to_integer(True, sk)
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
pub fn verify(pk: ByteArray, message: ByteArray, signature: ByteArray) -> Bool {
  let p = bls12_381_g1_uncompress(pk)

  // 1. Convert signature to a point.
  let s = bls12_381_g2_uncompress(signature)

  // 2. Hash the message to a point.
  let q = bls12_381_g2_hash_to_group(message, dst_basic_G2)

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
pub fn aggregate_signatures(signatures: List<ByteArray>) -> ByteArray {
  // Check if the list of signatures is empty.
  if list.length(signatures) <= 0 {
    // If the list is empty, fail the function.
    fail
  } else {
    // Use foldl to aggregate the signatures from left to right.
    foldl(
      signatures,
      point_zero_G2,
      // Start with the identity element in G2.
      fn(signature, sum) {
        // For each signature, uncompress it and add it to the current sum.
        bls12_381_g2_add(bls12_381_g2_uncompress(signature), sum)
      },
    )
      |> bls12_381_g2_compress
  }
}

/// Recursive function to compute the pairing product for multiple public keys and messages
///
/// Parameters:
/// * `pairs`: List<(ByteArray, ByteArray)> - a list of pairs, where each pair is a public key and a message
/// * `result`: MillerLoopResult - the current pairing product (C1)
///
/// Returns:
/// MillerLoopResult - the updated pairing product (C1)
///
fn recursive_pairing(
  pairs: List<(ByteArray, ByteArray)>,
  miller_loop: MillerLoopResult,
) {
  when pairs is {
    [] -> miller_loop
    [pair, ..pairs] -> {
      let (pk, message) = pair
      let p = bls12_381_g1_uncompress(pk)
      let q = bls12_381_g2_hash_to_group(message, dst_basic_G2)

      let pq = group_pairing(p, q)
      recursive_pairing(
        pairs,
        bls12_381_mul_miller_loop_result(pq, miller_loop),
      )
    }
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
pub fn verify_aggregate(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  signature: ByteArray,
) -> Bool {
  if length(pks) == 0 || length(messages) == 0 {
    fail @"empty pk or message!"
  } else {
    let z = zip(pks, messages)
    let (pk, message) =
      when head(z) is {
        Some(res) -> res
        _ -> fail @"empty list!"
      }

    let rest =
      when tail(z) is {
        Some(r) -> r
        _ ->
          []
      }

    // only 1 element
    let p = bls12_381_g1_uncompress(pk)
    let q = bls12_381_g2_hash_to_group(message, dst_basic_G2)
    let ml = group_pairing(p, q)

    let c1 = recursive_pairing(rest, ml)

    let s = bls12_381_g2_uncompress(signature)
    let c2 = group_pairing(point_base_G1, s)

    bls12_381_final_verify(c1, c2)
  }
}

// Tests
const sk = #"ed69a8c50cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

const pk =
  #"a80494fbe51f816f338146074af7ab070ee3f97e426b0d2c47718c3888d7e08ffd33abba7cff885191de2bf78b278dbb"

const msg1 = #"000001"

const msg2 = #"000002"

const signature1 =
  #"a87a83193fe19d2d6a235d173450291cba9551ad88a85795d4fc62ef0c37b640ce9bb4a363dbcc54b5cf5159031cb1fc1441c8b4d605e874a0e01d0bcb014cf7ce8f3373e8d216f3bf15af780dc7ee282c5bb682935a8c9e235f118396ae60b5"

const aggr_signature_12 =
  #"8dd9b3b23748d2bf42468eafde8d6d8dc5017cb7f0882b837d4439cd839feb7da42dff7e30f4e7221a82d8109e05ab3a0cf5a3b26716d71738187a11feece6f7cb4f61d1ceccbe6557a357baee25b2a09fce8a8e8d928c6449b3fbd5bd59cff7"

test test_sign() {
  let signature = sign(sk, msg1)
  signature == signature1
}

test test_skToPk() {
  let result = skToPk(sk)
  result == pk
}

test test_verify() {
  let pk = skToPk(sk)
  let sign = sign(sk, msg1)
  verify(pk, msg1, sign)
}

test test_aggregate_verify() {
  let pk = skToPk(sk)
  let sign0 = sign(sk, msg1)
  let sign1 = sign(sk, msg2)

  let aggr = aggregate_signatures([sign0, sign1])

  verify_aggregate([pk, pk], [msg1, msg2], aggr)
}

test test_aggregate_verify_1() {
  let pk = skToPk(sk)
  let sign = sign(sk, msg1)
  verify_aggregate([pk], [msg1], sign)
}

test test_aggregate_signatures() {
  let sign1 = sign(sk, msg1)
  let sign2 = sign(sk, msg2)

  let agg = aggregate_signatures([sign1, sign2])
  agg == aggr_signature_12
}
