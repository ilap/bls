//// @hidden
//// Tests for G2 message augmentation implementation

use bls/g2_aug as aug
use bls/tests/utils

/// Augmented mode prevents rogue-key attacks because each participant signs:
/// -   `H(pk || message)`
///
/// Meaning the public key is cryptographically bound to the signature.
///
/// Even if an attacker constructs a rogue public key, the forged aggregation
/// fails because the attacker cannot produce signatures corresponding to the
/// honest participants' `(pk || message)` inputs.
test g2_aug_rogue_key_attack_fails() {
  // Verification must fail because Aug binds pk into the message
  // Check lib/bls/utils.ak for the rogue key construction method.
  !aug.aggregate_verify(
    [utils.pk1, utils.pk2, utils.rogue_pk],
    [utils.message, utils.message, utils.message],
    utils.sig_fake,
  )
}
