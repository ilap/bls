//// This module implements operations for BLS12-381 signatures.
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
use aiken/list.{foldl, length}
use bls/constants.{dst_basic_G2, point_base_G1, point_zero_G1, point_zero_G2}
use bls/utils.{foldl2}

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
pub fn aggregate_publickeys(publickeys: List<ByteArray>) -> ByteArray {
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
pub fn verify_aggregate(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  signature: ByteArray,
) -> Bool {
  expect [pk, ..xs] = pks
  expect [msg, ..ys] = messages

  let p = bls12_381_g1_uncompress(pk)
  let q = bls12_381_g2_hash_to_group(msg, dst_basic_G2)
  let ml = group_pairing(p, q)
  let c1 =
    foldl2(
      xs,
      ys,
      ml,
      fn(pk, message, miller_loop) {
        let p = bls12_381_g1_uncompress(pk)
        let q = bls12_381_g2_hash_to_group(message, dst_basic_G2)
        let pq = group_pairing(p, q)
        bls12_381_mul_miller_loop_result(pq, miller_loop)
      },
    )

  let s = bls12_381_g2_uncompress(signature)
  let c2 = group_pairing(point_base_G1, s)

  bls12_381_final_verify(c1, c2)
}

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
const pk3 =
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

test test_sign() {
  let signature = sign(sk1, msg1)
  signature == sg1
}

test test_skToPk() {
  let result = skToPk(sk1)
  result == pk1
}

test test_verify() {
  verify(pk1, msg1, sg1)
}

test test_aggregate_verify_1() {
  verify_aggregate([pk1], [msg1], sg1)
}

test test_aggregate_verify_2() {
  verify_aggregate([pk1, pk2], [msg1, msg2], sg12)
}

test test_aggregate_verify_3() {
  verify_aggregate([pk1, pk2, pk3], [msg1, msg2, msg3], sg123)
}

test test_aggregate_signatures() {
  let agg = aggregate_signatures([sg1, sg2])
  agg == sg12
}

test test_aggregate_shuffled_signatures_6x() {
  sg123 == aggregate_signatures([sg1, sg2, sg3]) && sg123 == aggregate_signatures(
    [sg1, sg3, sg2],
  ) && sg123 == aggregate_signatures([sg2, sg3, sg1]) && sg123 == aggregate_signatures(
    [sg2, sg1, sg3],
  ) && sg123 == aggregate_signatures([sg3, sg1, sg2]) && sg123 == aggregate_signatures(
    [sg3, sg2, sg1],
  )
}

test test_aggregate_shuffled_signatures_2_6x() {
  sg123 == aggregate_signatures([sg12, sg3]) && sg123 == aggregate_signatures(
    [sg3, sg12],
  )
}

test test_aggregate_publickeys() {
  let agg = aggregate_publickeys([pk1, pk2])
  agg == pk12
}

test test_aggregate_shuffled_publickes_6x() {
  pk123 == aggregate_publickeys([pk1, pk2, pk3]) && pk123 == aggregate_publickeys(
    [pk1, pk3, pk2],
  ) && pk123 == aggregate_publickeys([pk2, pk3, pk1]) && pk123 == aggregate_publickeys(
    [pk2, pk1, pk3],
  ) && pk123 == aggregate_publickeys([pk3, pk1, pk2]) && pk123 == aggregate_publickeys(
    [pk3, pk2, pk1],
  )
}

test test_aggregate_shuffled_publickes_2_6x() {
  pk123 == aggregate_publickeys([pk12, pk3]) && pk123 == aggregate_publickeys(
    [pk3, pk12],
  )
}
