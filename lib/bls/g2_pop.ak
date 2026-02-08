//// Augmented (Aug) signing mode + Proof-of-Possession (PoP) helpers
////
//// In Augmented mode the signed message is:
//// ```
////     H(pk || message)
//// ```
//// where the signer’s public key is prepended to the message before hashing.
//// This binds the public key to the signature and protects aggregation from
//// rogue-key attacks, allowing safe use even when keys are not PoP-verified.
////
//// PoP helpers are included for key-registration workflows, enabling a
//// participant to prove ownership of the private key corresponding to a
//// registered public key.

use aiken/builtin
use bls/core
use bls/types

/// Convert a private key to its corresponding public key.
pub fn skToPk(sk: ByteArray) -> ByteArray {
  core.internal_skToPk(sk)
}

/// Create an Augmented BLS signature.
/// The public key is appended to the message before signing.
pub fn sign(sk: ByteArray, pk: ByteArray, message: ByteArray) -> ByteArray {
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

/// Used at key-registration time to ensure a participant actually controls the
/// private key corresponding to the registered public key.
/// Generate Proof-of-Possession for a public key.
pub fn pop_prove(sk: ByteArray) -> ByteArray {
  let pk = skToPk(sk)
  core.internal_sign(sk, pk, types.Pop)
}

/// Verify a Proof-of-Possession signature.
pub fn pop_verify(pk: ByteArray, pop_sig: ByteArray) -> Bool {
  core.internal_verify(pk, pk, pop_sig, types.Pop)
}

/// Aggregate multiple signatures into one aggregated signature.
pub fn aggregate_signatures(sigs: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_signatures(sigs)
}

/// Aggregate multiple public keys into a single aggregated public key.
pub fn aggregate_publickeys(pks: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_publickeys(pks)
}

/// Verify aggregated signatures using PoP-validated keys.
///
/// > [!IMPORTANT]
/// > Security Note:
/// > This verification assumes that all public keys participating in aggregation
/// > were previously validated using PoP during registration. If keys are not
/// > PoP-verified, use Augmented aggregation verification instead.
pub fn aggregate_verify(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  sig: ByteArray,
) -> Bool {
  core.internal_aggregate_verify(pks, messages, sig, types.Pop)
}
