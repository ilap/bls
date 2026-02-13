//// Augmented (Aug) BLS signing mode
////
//// In augmented mode the signed message is:
////
////     H(pk || message)
////
//// The signer’s public key is prepended to the message before hashing,
//// binding the public key to the signature and mitigating rogue-key
//// attacks, allowing safe aggregation even when public keys are not
//// proof-of-possession (PoP) verified.

use aiken/builtin
use aiken/collection/list
use bls/core
use bls/types

/// Convert a private key to its corresponding public key.
pub fn skToPk(sk: ByteArray) -> ByteArray {
  core.internal_skToPk(sk)
}

/// Create an Augmented BLS signature.
/// The public key is concatenated with the message before signing.
pub fn sign(sk: ByteArray, message: ByteArray) -> ByteArray {
  let pk = skToPk(sk)
  core.internal_sign(sk, builtin.append_bytearray(pk, message), types.Aug)
}

/// Verify an Augmented BLS signature.
pub fn verify(pk: ByteArray, message: ByteArray, sig: ByteArray) -> Bool {
  core.internal_verify(
    pk,
    builtin.append_bytearray(pk, message),
    sig,
    types.Aug,
  )
}

/// Aggregate multiple signatures into a single aggregated signature.
pub fn aggregate_signatures(sigs: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_signatures(sigs)
}

/// Aggregate multiple public keys into a single aggregated public key.
pub fn aggregate_publickeys(pks: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_publickeys(pks)
}

/// Verify aggregated Augmented signatures.
///
/// For Aug mode, each signer signs (pk || message), therefore during aggregate
/// verification we must construct the same concatenated inputs for each signer
/// before calling the core verification routine.
pub fn aggregate_verify(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  sig: ByteArray,
) -> Bool {
  // Create list of (pk || message) values used during signing
  let concatenated = list.map2(pks, messages, builtin.append_bytearray)
  core.internal_aggregate_verify(pks, concatenated, sig, types.Aug)
}
