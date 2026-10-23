//! Exact signed integer arithmetic for the host's reference semantics of a claim.
//!
//! The circuits never wrap; this is the same mathematics on unbounded integers, used to tell a
//! prover, before any proof is attempted, that a claim is false for the values it holds (and as the
//! independent oracle the tests compare the circuits against). Magnitudes are little-endian base
//! 2^32 digits with no trailing zero digit, and zero is never negative, so equality is structural.

use std::cmp::Ordering;

use super::int::Number;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Int {
    negative: bool,
    magnitude: Vec<u32>,
}

fn trim(mut digits: Vec<u32>) -> Vec<u32> {
    while digits.last() == Some(&0) {
        digits.pop();
    }
    digits
}

fn compare_magnitude(a: &[u32], b: &[u32]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn add_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let sum = u64::from(*a.get(i).unwrap_or(&0)) + u64::from(*b.get(i).unwrap_or(&0)) + carry;
        out.push(sum as u32);
        carry = sum >> 32;
    }
    out.push(carry as u32);
    trim(out)
}

/// `a - b` for `a >= b`.
fn subtract_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i64;
    for (i, digit) in a.iter().enumerate() {
        let mut difference = i64::from(*digit) - i64::from(*b.get(i).unwrap_or(&0)) - borrow;
        borrow = i64::from(difference < 0);
        if difference < 0 {
            difference += 1 << 32;
        }
        out.push(difference as u32);
    }
    trim(out)
}

fn multiply_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = vec![0u32; a.len() + b.len()];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, y) in b.iter().enumerate() {
            let total = u64::from(out[i + j]) + u64::from(*x) * u64::from(*y) + carry;
            out[i + j] = total as u32;
            carry = total >> 32;
        }
        out[i + b.len()] = carry as u32;
    }
    trim(out)
}

impl Int {
    fn new(negative: bool, magnitude: Vec<u32>) -> Self {
        let magnitude = trim(magnitude);
        Self {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        }
    }

    pub(super) fn add(&self, other: &Self) -> Self {
        if self.negative == other.negative {
            return Self::new(
                self.negative,
                add_magnitude(&self.magnitude, &other.magnitude),
            );
        }
        match compare_magnitude(&self.magnitude, &other.magnitude) {
            Ordering::Less => Self::new(
                other.negative,
                subtract_magnitude(&other.magnitude, &self.magnitude),
            ),
            _ => Self::new(
                self.negative,
                subtract_magnitude(&self.magnitude, &other.magnitude),
            ),
        }
    }

    pub(super) fn mul(&self, other: &Self) -> Self {
        Self::new(
            self.negative != other.negative,
            multiply_magnitude(&self.magnitude, &other.magnitude),
        )
    }

    pub(super) fn compare(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => compare_magnitude(&self.magnitude, &other.magnitude),
            (true, true) => compare_magnitude(&other.magnitude, &self.magnitude),
        }
    }

    pub(super) fn zero() -> Self {
        Self::new(false, Vec::new())
    }
}

impl From<Number> for Int {
    fn from(number: Number) -> Self {
        let (negative, magnitude) = number.parts();
        Self::new(
            negative,
            (0..4).map(|i| (magnitude >> (32 * i)) as u32).collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(value: i128) -> Int {
        Int::from(Number::from(value))
    }

    #[test]
    fn matches_i128_where_i128_does_not_overflow() {
        let samples = [
            0i128,
            1,
            -1,
            7,
            -9,
            1 << 62,
            -(1 << 62),
            123_456_789_012_345,
        ];
        for a in samples {
            for b in samples {
                assert_eq!(int(a).add(&int(b)), int(a + b), "{a}+{b}");
                assert_eq!(int(a).mul(&int(b)), int(a * b), "{a}*{b}");
                assert_eq!(int(a).compare(&int(b)), a.cmp(&b), "{a}<=>{b}");
            }
        }
    }

    #[test]
    fn exceeds_the_native_range_without_wrapping() {
        let max = Int::from(Number::from(u128::MAX));
        let doubled = max.add(&max);
        assert_eq!(doubled.compare(&max), Ordering::Greater);
        assert_eq!(
            doubled.add(&int(-1).mul(&max)),
            max,
            "(2m) - m == m across the u128 boundary"
        );
        let square = max.mul(&max);
        assert_eq!(square.compare(&doubled), Ordering::Greater);
        assert_eq!(square.magnitude.len(), 8, "(2^128-1)^2 needs 256 bits");
    }

    #[test]
    fn zero_is_canonical() {
        assert_eq!(int(5).add(&int(-5)), Int::zero());
        assert_eq!(int(-3).mul(&int(0)), Int::zero());
        assert_eq!(int(-0).compare(&Int::zero()), Ordering::Equal);
    }
}
