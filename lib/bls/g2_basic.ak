//// Basic BLS signing mode
////
//// Basic BLS aggregation is vulnerable to rogue-key attacks if the public
//// keys participating in aggregation were not previously verified using a
//// proof-of-possession (PoP) registration procedure.
////
//// This mode should only be used when:
////   - all public keys are trusted, or
////   - keys were validated with PoP at registration time.
////
//// If keys are untrusted or dynamic, prefer Augmented (Aug) or PoP modes.
////
//// > [!IMPORTANT]
//// > Using Basic mode with unverified or untrusted keys can compromise
//// > the security of aggregated signatures.

use bls/core
use bls/types
use bls/utils

/// Convert a private key to its corresponding public key.
pub fn skToPk(sk: ByteArray) -> ByteArray {
  core.internal_skToPk(sk)
}

/// Create a Basic-mode BLS signature.
/// Signs the raw message without public-key augmentation.
pub fn sign(sk: ByteArray, message: ByteArray) -> ByteArray {
  core.internal_sign(sk, message, types.Basic)
}

/// Verify a Basic-mode BLS signature.
pub fn verify(pk: ByteArray, message: ByteArray, sig: ByteArray) -> Bool {
  core.internal_verify(pk, message, sig, types.Basic)
}

/// Aggregate multiple signatures into a single signature.
/// All signatures must be generated in Basic mode.
pub fn aggregate_signatures(sigs: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_signatures(sigs)
}

/// Aggregate multiple public keys into a single public key.
/// Keys MUST have been PoP-verified prior to aggregation.
pub fn aggregate_publickeys(pks: List<ByteArray>) -> ByteArray {
  core.internal_aggregate_publickeys(pks)
}

/// Verify an aggregated signature against aggregated participants.
///
/// SECURITY NOTE:
/// This verification is safe only if:
///   - all public keys were previously validated via PoP, OR
///   - the system ensures keys cannot be maliciously crafted.
///
/// Otherwise the system may be vulnerable to rogue-key attacks.
pub fn aggregate_verify(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  sig: ByteArray,
) -> Bool {
  core.internal_aggregate_verify(pks, messages, sig, types.Basic)
}

/// Verify an aggregated signature for Basic BLS mode, enforcing that
/// all messages are distinct.
///
/// SECURITY NOTE:
/// Basic BLS aggregation is vulnerable to rogue-key attacks if duplicate
/// messages are allowed. This function ensures safety by checking that
/// each message is unique before performing the aggregation verification.
///
/// Use this function when aggregating arbitrary or untrusted public keys
/// to prevent potential forgery attacks.
pub fn aggregate_distinct_verify(
  pks: List<ByteArray>,
  messages: List<ByteArray>,
  sig: ByteArray,
) -> Bool {
  if !utils.all_unique(messages) {
    False
  } else {
    core.internal_aggregate_verify(pks, messages, sig, types.Basic)
  }
}
