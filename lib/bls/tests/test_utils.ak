use aiken/builtin
use bls/utils

test foldl2_sum() {
  let result =
    utils.foldl2([1, 2, 3], [4, 5, 6], 0, fn(a, b, acc) { acc + a + b })
  result == 21
}

test foldl2_concat_strings() {
  let result =
    utils.foldl2(
      [@"a", @"b"],
      [@"x", @"y"],
      @"",
      fn(a, b, acc) { builtin.append_string(acc, builtin.append_string(a, b)) },
    )
  result == @"axby"
}

test foldl2_empty_lists() {
  let result = utils.foldl2([], [], 100, fn(_a, _b, acc) { acc + 1 })
  result == 100
}

/// ------------------------
/// Tests for trace_message
/// ------------------------
test trace_message_basic() {
  let result = utils.trace_message(@"Value", 42)
  result == @"Value: 42"
}

test trace_message_empty_string() {
  let result = utils.trace_message(@"", "")
  result == @": h''"
}

test trace_message_boolean() {
  let true = utils.trace_message(@"", True)
  let false = utils.trace_message(@"", False)
  and {
    true == @": 122([])",
    false == @": 121([])",
  }
}

/// ------------------------
/// Tests for all_unique
/// ------------------------
test all_unique_false() {
  let xs = [#"01", #"02", #"03", #"01", #"04"]
  !utils.all_unique(xs)
}

test all_unique_true() {
  let xs = [#"04", #"02", #"03", #"01"]
  utils.all_unique(xs)
}

test all_unique_empty() {
  let xs: List<ByteArray> = []
  utils.all_unique(xs)
}

test all_unique_single() {
  let xs = [#"ff"]
  utils.all_unique(xs)
}
