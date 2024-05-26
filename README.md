# High level BSL12-381 functions for Aiken 

## Introduction

Welcome to the BLS12-381 library for the Aiken Cardano smart-contract language! This library is designed to simplify the use of BLS12-381 signatures in Aiken by extending the language built-ins with a comprehensive suite of data types, functions, constants, and aliases.

With this library, you can seamlessly implement advanced smart contracts on the Cardano blockchain utilizing the BLS12-381 signature scheme.

## TODOS

Core Functions Implemented
- [ ] **keygen**: Generate private key.
- [x] **skToPk**: Convert secret key to public key.
- [x] **sign**: Sign messages with private key.
- [x] **verify**: Verify signatures with the public key.
- [x] **aggregate**: Combine multiple signatures.
- [x] **aggregate_verify**: Verify aggregated signatures.

Aug Functions Implemented
- [ ] **TBD**

PoP functions Implemented
- [ ] **TBD**

## Getting Started
To get started with this library, make sure you have the Aiken environment set up and follow the installation instructions provided in the documentation.

## Usage
Detailed usage examples and API documentation can be found in the docs directory. Here is a quick example to get you started:

``` gleam
import ilap/bls.{keygen, skToPk, sign, verify}

test test_bls () {
  let sk = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let pk = skToPk(sk)
  let message = "Hello, Aiken!"

  let signature = sign(sk, message)

  verify(pk, message, signature)
}
```

## Resources

- [BLS Signatures Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature#name-aggregate)


## Contributing
We welcome contributions to enhance the functionality and usabilioty of this library. Please refer to the [CONTRIBUTING.md](./CONTRIBUTING.md) file for guidelines on how to contribute.

## License
This project is licensed under the `Apache 2.0 License` - see the [LICENSE](./LICENSE) file for details.

