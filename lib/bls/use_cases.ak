//// 
//// Intersting use cases of the library usage
//// 

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