# High level BLS12-381 functions for Aiken


[![Licence](https://img.shields.io/github/license/aiken-lang/stdlib?style=for-the-badge)](https://github.com/ilap/bls/blob/main/LICENSE)
[![Continuous Integration](https://img.shields.io/github/actions/workflow/status/aiken-lang/stdlib/continuous-integration.yml?style=for-the-badge)](https://github.com/ilap/bls/actions/workflows/ci.yml)
[![GitHub Pages](https://img.shields.io/badge/GitHub_Pages-Online-brightgreen?style=for-the-badge)](https://ilap.github.io/bls/)

## Introduction

Welcome to the BLS12-381 library for the Aiken Cardano smart-contract language! This library is designed to simplify the use of BLS12-381 signatures in Aiken by extending the language built-ins with a comprehensive suite of data types, functions, constants, and aliases.

With this library, you can seamlessly implement advanced smart contracts on the Cardano blockchain utilizing the BLS12-381 signature scheme.

## TODOS

Core Functions Implemented

- [ ] **keygen**: Generate private key.
- [x] **skToPk**: Convert secret key to public key.
- [x] **sign**: Sign messages with private key.
- [x] **verify**: Verify signatures with the public key.
- [x] **aggregate_signatures**: Combine multiple signatures.
- [x] **aggregate_publickeys**: Combine multiple public keys.
- [x] **aggregate_verify**: Verify aggregated signatures.

Aug Functions Implemented

- [ ] **TBD**

PoP functions Implemented

- [ ] **TBD**

## Getting Started

To get started with this library, make sure you have the Aiken environment set up and follow the installation instructions provided in the documentation.

## Usage

Detailed usage examples and API documentation can be found in the docs directory. Here is a quick example to get you started:

- add the following dependency to aiken.toml

```aiken.toml
[[dependencies]]
name = "ilap/bls"
version = "0.3.0"
source = "github"
```
- use library in Aiken code like below

```aiken
use ilap/bls/core.{sign, skToPk, verify}

test test_bls () {
  let sk = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let pk = skToPk(sk)
  let message = "Hello, Aiken!"

  let signature = sign(sk, message)

  verify(pk, message, signature)
}
```

## Use case of usage

<details>
<summary>Aggregate signature case</summary>

```aiken
use bls/core.{aggregate_signatures, sign, skToPk, verify_aggregate}

test three_party_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = skToPk(sk3)

  let message1 = "Hello, Aiken from party 1!"
  let message2 = "Hello, Aiken from party 2!"
  let message3 = "Hello, Aiken from party 3!"

  let sig1 = sign(sk1, message1)
  let sig2 = sign(sk2, message2)
  let sig3 = sign(sk3, message3)

  let sig_aggr = aggregate_signatures([sig1, sig2, sig3])

  // full signature aggregation
  let full_aggr_predicate = verify_aggregate([pk1,pk2,pk3], [message1,message2,message3], sig_aggr)

  // partial signature aggregation
  let sig13_aggr = aggregate_signatures([sig1, sig3])  
  full_aggr_predicate && verify_aggregate([pk1,pk3], [message1,message3], sig13_aggr)
}
```

</details>

<details>
<summary>Aggregate signature case</summary>

```aiken
use bls/core.{aggregate_signatures, sign, skToPk, verify_aggregate}

test three_party_signature_and_public_key_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = skToPk(sk3)

  let message = "Hello, Aiken from all parties!"

  let sig1 = sign(sk1, message)
  let sig2 = sign(sk2, message)
  let sig3 = sign(sk3, message)

  let sig_aggr = aggregate_signatures([sig1, sig2, sig3])

  let pk_aggr = aggregate_publickeys([pk1, pk2, pk3])

  verify_aggregate([pk_aggr], [message], sig_aggr)
}
```

</details>

## BLS12-381 Technical Brief

- **Embedding degree**: 12 i.e. the complexity of the pairing operation.
- **Field Size (𝑝)**: A large prime number defining the finite field i.e. 𝔽𝑝. The prime in the finite field is 381-bit.
- **Prime Order (r)**: The number of points on the curve e.g. `𝑦^2=𝑥^3+4` for `𝑥∈{0,𝔽𝑝−1}`. The number of points on the elliptic curve (excluding the point at infinity) is a prime number.
- **Security level**: BLS12-381 provides an approximate 128-bit security level, given that its complexity is around `≈√𝑟` i.e. `𝑟≈2^256`.
- **Private key**: A scalar in `𝔽𝑝` which means `∈{0,𝑝−1}`. The size is 381 bits ~48 bytes.
- **Identity Element**: The multiplicative identity (1).
- **Bilinear pairing** : A function `𝑒:𝐺1×𝐺2→𝐺𝑇` with the following properties:

  - **Non-degeneracy**: `𝑒(𝑔1,𝑔2)≠1` for some `𝑔1∈𝐺1` and `𝑔2∈𝐺2`.
  - **Bilinearity**: `𝑒(𝑎𝑔1,𝑏𝑔2)=𝑒(𝑔1,𝑔2)𝑎𝑏` for all `𝑎,𝑏∈𝔽𝑝` and `𝑔1∈𝐺1` and `𝑔2∈𝐺2`.
  - **Computability**: There exists an efficient algorithm to compute `𝑒(𝑔1,𝑔2)` for all `𝑔1∈𝐺1` and `𝑔2∈𝐺2`.

- **Group Definitions**:
  - **G1**: This group consists of points on the elliptic curve over the base field `𝐹𝑝` (`𝑦^2=𝑥^3+4`).
  - **G2**:: This group consists of points on the twisted curve over an extension field `𝐹𝑝^2` (`𝑦^2=𝑥^3+4(1+i)`).
  - **GT**: This is the multiplicative group of a larger field `𝐹𝑝12`, used as the result of the pairing operation.

## Resources

- [BLS Signatures Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature)

## Contributing

We welcome contributions to enhance the functionality and usabilioty of this library. Please refer to the [CONTRIBUTING.md](./CONTRIBUTING.md) file for guidelines on how to contribute.

## License

This project is licensed under the `Apache 2.0 License` - see the [LICENSE](./LICENSE) file for details.
