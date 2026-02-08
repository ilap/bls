//// @hidden
//// Tests for G2 proof of possession implementation

use bls/g2_pop as pop
use bls/tests/utils

/// Rogue attack works because the attacker can freely choose a derived public key.
/// PoP forces every registered key to prove:
/// - `that I know the private key for THIS exact public key.`
///
/// The attacker cannot produce a PoP for the forged rogue_pk, so the key never enters
/// the aggregation set.
test g2_pop_prevents_rogue_key_attack() {
  // Honest PoPs
  let pop1 = pop.pop_prove(utils.sk1)
  let pop2 = pop.pop_prove(utils.sk2)

  expect pop.pop_verify(utils.pk1, pop1)
  expect pop.pop_verify(utils.pk2, pop2)

  // PoP verification fails → registration rejected
  // Check lib/bls/utils.ak for the rogue key construction method.
  !pop.pop_verify(utils.rogue_pk, pop1)
}
