use aiken/builtin
use aiken/cbor

pub fn trace_message(message: String, data: Data) -> String {
  let prefix = builtin.append_string(message, @": ")
  builtin.append_string(prefix, cbor.diagnostic(data))
}
