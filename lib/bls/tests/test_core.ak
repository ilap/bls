use bls/core.{key_gen}

/// Test vector from algorand's reference implementation:
/// https://github.com/algorand/bls_sigs_ref/blob/b499fdc44b303e681dd9f5dd8f889398da708b59/rust-impl/src/test.rs#L27
///
test core_key_gen() {
  let message = "hello world (it's a secret!)"

  let sk = key_gen(message, "")

  //let sk_bytes = bytearray.from_int_big_endian(sk, 32)
  let expected =
    #"0e0db52716a4a2377628c92366acec81817115ccf9b77ad7d8aa1dc5c40d91d4"
  sk == expected
}
