use subtle::ConstantTimeEq;

/// Constant-time equality check for fixed-size byte arrays.
///
/// Returns `true` iff `a == b` without leaking which bytes differed or at which
/// index the comparison terminated.
pub fn timing_safe_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.as_ref().ct_eq(b.as_ref()).into()
}
