////
//// BLS12-381
//// u = -0xd201000000010000 =−2^63−2^62−2^60−2^57−2^48−2^16 , with a hamming weight of 6
//// q = (z - 1)^2(z^4 - z^2 + 1) / 3 + z = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
//// r = z^4 - z^2 + 1 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 = 52435875175126190479447740508185965837690552500527637822603658699938581184513
////
//// k = 12
//// Where:
////    `u`: low-hamming weight.
////    `q`: field generator a 381-bit prime the field Fq generated.
////    `r`: prime order, the size (255-bits) of the pairing-friendly subgroups.
////    `k`: embedding degree of 12.
////

/// `r` (255-bit prime order): The size of the pairing-friendly subgroups (G1, G2, GT).
pub const prime_order =
  52435875175126190479447740508185965837690552500527637822603658699938581184513

/// DSTs - The domain separation tags for the hash-to-curve function.
pub const dst_basic_G1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

pub const dst_basic_G2 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

pub const point_zero_G1 =
  #<Bls12_381, G1>"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

pub const point_zero_G2 =
  #<Bls12_381, G2>"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

pub const point_base_G1 =
  #<Bls12_381, G1>"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"

pub const point_base_G2 =
  #<Bls12_381, G2>"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
