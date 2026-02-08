/// BLS signature mode determining how messages are prepared for
/// signing and verification:
/// - `Basic`: Standard BLS.
/// - `Aug`: Message augmented with the public key.
/// - `Pop`: Proof-of-Possession mode.
pub type BlsMode {
  Basic
  Aug
  Pop
}
