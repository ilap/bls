use aiken/builtin
use aiken/cbor

// Reducing two lists from left to right. Handy for aggregation operations.
// It fails when `other` list is smaller than `self`
pub fn foldl2(
  self: List<a>,
  other: List<b>,
  value: c,
  with: fn(a, b, c) -> c,
) -> c {
  when self is {
    [] -> value
    [x, ..xs] -> {
      expect [y, ..ys] = other
      foldl2(xs, ys, with(x, y, value), with)
    }
  }
}

pub fn trace_message(message: String, data: Data) -> String {
  let prefix = builtin.append_string(message, @": ")
  builtin.append_string(prefix, cbor.diagnostic(data))
}
