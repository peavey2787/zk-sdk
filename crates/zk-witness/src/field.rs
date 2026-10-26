//! The prime fields the solver works over. Circuits name their prime in the `.r1cs` header; the
//! calculator only accepts files over the field it was instantiated with.

use std::fmt::Debug;

/// A prime field with canonical elements. Implemented here for KoalaBear and by backend crates
/// for their own fields, so one solver serves every backend.
pub trait Field {
    type Element: Copy + Eq + Debug;
    const ZERO: Self::Element;
    const ONE: Self::Element;
    /// The modulus as circom writes it in `.r1cs`/`.wtns` headers: little-endian, fixed width.
    fn modulus_le() -> Vec<u8>;
    fn add(a: Self::Element, b: Self::Element) -> Self::Element;
    fn neg(a: Self::Element) -> Self::Element;
    fn mul(a: Self::Element, b: Self::Element) -> Self::Element;
    /// `a` must be non-zero.
    fn inv(a: Self::Element) -> Self::Element;
    fn is_canonical(a: Self::Element) -> bool;
    /// Decode a fixed-width little-endian element; `None` when it is not below the modulus.
    fn from_le(bytes: &[u8]) -> Option<Self::Element>;
    fn to_le(a: Self::Element) -> Vec<u8>;
    /// The element as an integer when it is below 2^128 (bit decoding needs only small values).
    fn to_u128(a: Self::Element) -> Option<u128>;
    fn from_u64(v: u64) -> Self::Element;

    fn sub(a: Self::Element, b: Self::Element) -> Self::Element {
        Self::add(a, Self::neg(b))
    }
}

/// KoalaBear, p = 2^31 - 2^24 + 1. Elements are canonical `u64 < P`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KoalaBear;

pub const P: u64 = 2_130_706_433;

impl Field for KoalaBear {
    type Element = u64;
    const ZERO: u64 = 0;
    const ONE: u64 = 1;

    fn modulus_le() -> Vec<u8> {
        (P as u32).to_le_bytes().to_vec()
    }

    fn add(a: u64, b: u64) -> u64 {
        (a + b) % P
    }

    fn neg(a: u64) -> u64 {
        (P - a) % P
    }

    fn mul(a: u64, b: u64) -> u64 {
        a * b % P
    }

    /// Inverse by Fermat.
    fn inv(a: u64) -> u64 {
        let (mut result, mut base, mut exp) = (1, a, P - 2);
        while exp > 0 {
            if exp & 1 == 1 {
                result = Self::mul(result, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }
        result
    }

    fn is_canonical(a: u64) -> bool {
        a < P
    }

    fn from_le(bytes: &[u8]) -> Option<u64> {
        let value = u64::from(u32::from_le_bytes(bytes.try_into().ok()?));
        (value < P).then_some(value)
    }

    fn to_le(a: u64) -> Vec<u8> {
        (a as u32).to_le_bytes().to_vec()
    }

    fn to_u128(a: u64) -> Option<u128> {
        Some(u128::from(a))
    }

    fn from_u64(v: u64) -> u64 {
        v % P
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type K = KoalaBear;

    #[test]
    fn inverse_and_subtraction() {
        for a in [1, 2, 18, P - 1, 123_456_789] {
            assert_eq!(K::mul(a, K::inv(a)), 1);
        }
        assert_eq!(K::sub(3, 5), P - 2);
        assert_eq!(K::add(P - 1, 1), 0);
        assert_eq!(K::neg(0), 0);
    }

    #[test]
    fn encoding_rejects_non_canonical_values() {
        assert_eq!(K::from_le(&K::to_le(P - 1)), Some(P - 1));
        assert_eq!(K::from_le(&(P as u32).to_le_bytes()), None);
        assert_eq!(K::from_le(&[1, 2, 3]), None);
    }
}
