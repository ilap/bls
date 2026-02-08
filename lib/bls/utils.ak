use aiken/builtin
use aiken/cbor
use aiken/collection/list

/// Reduce two lists simultaneously from left to right using an accumulator.
///
/// Applies the function `with` to each pair of elements `(a, b)` from `self`
/// and `other`, threading the accumulator `value` through each step.
/// The traversal stops when `self` becomes empty.
///
/// > [!IMPORTANT]
/// > This function fails if `other` is shorter than `self`, because each
/// > element of `self` expects a corresponding element in `other`.
///
/// ```aiken
/// foldl2([1,2,3], [4,5,6], 0, fn(a, b, acc) { acc + a + b }) == 21
/// ```
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

/// Produce a diagnostic trace string consisting of a message followed by the
/// CBOR diagnostic representation of the provided `data`.
///
/// The result can be used for debugging output or structured tracing,
/// combining a human-readable prefix with serialized `Data`.
///
/// ```aiken
/// trace_message(@"datum", some_data)
/// ```
pub fn trace_message(message: String, data: Data) -> String {
  let prefix = builtin.append_string(message, @": ")
  builtin.append_string(prefix, cbor.diagnostic(data))
}

/// Check whether all elements in a list are unique.
///
/// Returns `True` if no duplicates are found, `False` otherwise.
///
/// This is used in Basic BLS aggregation to ensure that all messages
/// are distinct, which is necessary to prevent rogue-key attacks.
///
/// Example:
/// ```aiken
/// all_unique([#"01", #"02", #"03"]) == True
/// all_unique([#"01", #"02", #"01"]) == False
/// ```
pub fn all_unique(xs: List<ByteArray>) -> Bool {
  when xs is {
    [] -> True
    [x, ..rest] ->
      if list.any(rest, fn(y) { y == x }) {
        False
      } else {
        all_unique(rest)
      }
  }
}
