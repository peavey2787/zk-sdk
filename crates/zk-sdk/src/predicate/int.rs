//! Fixed-width integers as the circuits see them: unsigned, little-endian 16-bit limbs.
//!
//! A signed integer of width `w` is carried as `v + 2^(w-1)`, which preserves order, so one
//! unsigned comparison circuit serves both interpretations. [`IntType`] records width and
//! signedness; [`Number`] is a mathematical integer converted (and range-checked) for a type.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Result, ZkError};

const LIMB_BITS: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Width {
    W32,
    W64,
    W128,
}

impl Width {
    pub fn bits(self) -> u32 {
        match self {
            Self::W32 => 32,
            Self::W64 => 64,
            Self::W128 => 128,
        }
    }

    pub fn limbs(self) -> usize {
        (self.bits() / LIMB_BITS) as usize
    }
}

/// Width and signedness of a committed integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntType {
    pub width: Width,
    pub signed: bool,
}

impl IntType {
    pub const U32: Self = Self::new(Width::W32, false);
    pub const I32: Self = Self::new(Width::W32, true);
    pub const U64: Self = Self::new(Width::W64, false);
    pub const I64: Self = Self::new(Width::W64, true);
    pub const U128: Self = Self::new(Width::W128, false);
    pub const I128: Self = Self::new(Width::W128, true);

    pub const fn new(width: Width, signed: bool) -> Self {
        Self { width, signed }
    }

    /// The offset-binary form of `number`: an unsigned value below `2^width`. Fails when the
    /// number does not fit this type, so nothing is silently wrapped or saturated.
    pub fn encode(self, number: Number) -> Result<u128> {
        let bits = self.width.bits();
        let half = 1u128 << (bits - 1);
        let out_of_range = || ZkError::Predicate(format!("{number} does not fit {self}"));
        if !self.signed {
            let fits = !number.negative && (bits == 128 || number.magnitude < 1u128 << bits);
            return fits.then_some(number.magnitude).ok_or_else(out_of_range);
        }
        match (number.negative, number.magnitude) {
            (true, magnitude) if magnitude <= half => Ok(half - magnitude),
            (false, magnitude) if magnitude < half => Ok(half + magnitude),
            _ => Err(out_of_range()),
        }
    }

    /// The little-endian 16-bit limbs of an encoded value.
    pub fn limbs(self, encoded: u128) -> Vec<u64> {
        (0..self.width.limbs())
            .map(|i| u64::from((encoded >> (i as u32 * LIMB_BITS)) as u16))
            .collect()
    }
}

impl std::fmt::Display for IntType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            if self.signed { "i" } else { "u" },
            self.width.bits()
        )
    }
}

impl std::str::FromStr for IntType {
    type Err = ZkError;

    fn from_str(name: &str) -> Result<Self> {
        let invalid = || {
            ZkError::Predicate(format!(
                "unknown integer type `{name}` (u32 i32 u64 i64 u128 i128)"
            ))
        };
        let (signed, digits) = match name.split_at_checked(1).ok_or_else(invalid)? {
            ("u", digits) => (false, digits),
            ("i", digits) => (true, digits),
            _ => return Err(invalid()),
        };
        let width = match digits {
            "32" => Width::W32,
            "64" => Width::W64,
            "128" => Width::W128,
            _ => return Err(invalid()),
        };
        Ok(Self::new(width, signed))
    }
}

/// A mathematical integer in `[-2^127, 2^128)`, convertible from every primitive integer type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Number {
    negative: bool,
    magnitude: u128,
}

impl Zeroize for Number {
    fn zeroize(&mut self) {
        self.negative.zeroize();
        self.magnitude.zeroize();
    }
}

impl Number {
    /// Sign and absolute value.
    pub(super) fn parts(self) -> (bool, u128) {
        (self.negative, self.magnitude)
    }

    /// `self + other` for two non-negative numbers; `None` on overflow of `u128` or a negative input.
    pub fn checked_add_unsigned(self, other: Self) -> Option<Self> {
        (!self.negative && !other.negative)
            .then(|| self.magnitude.checked_add(other.magnitude))
            .flatten()
            .map(Self::from)
    }
}

impl std::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            if self.negative { "-" } else { "" },
            self.magnitude
        )
    }
}

impl std::str::FromStr for Number {
    type Err = ZkError;

    fn from_str(text: &str) -> Result<Self> {
        let invalid =
            || ZkError::Predicate(format!("`{text}` is not an integer in [-2^127, 2^128)"));
        match text.strip_prefix('-') {
            Some(digits) => digits
                .parse::<u128>()
                .ok()
                .filter(|m| *m <= 1u128 << 127)
                .map(|magnitude| Self {
                    negative: magnitude != 0,
                    magnitude,
                })
                .ok_or_else(invalid),
            None => text.parse::<u128>().map(Self::from).map_err(|_| invalid()),
        }
    }
}

impl Serialize for Number {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Number {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

macro_rules! unsigned_numbers {
    ($($t:ty),*) => {$(
        impl From<$t> for Number {
            fn from(value: $t) -> Self {
                Self { negative: false, magnitude: u128::from(value) }
            }
        }
    )*};
}

macro_rules! signed_numbers {
    ($($t:ty),*) => {$(
        impl From<$t> for Number {
            fn from(value: $t) -> Self {
                Self { negative: value < 0, magnitude: i128::from(value).unsigned_abs() }
            }
        }
    )*};
}

unsigned_numbers!(u8, u16, u32, u64, u128);
signed_numbers!(i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_range_is_exact() {
        assert_eq!(IntType::U32.encode(0.into()).unwrap(), 0);
        assert_eq!(
            IntType::U32.encode(u32::MAX.into()).unwrap(),
            u128::from(u32::MAX)
        );
        assert!(IntType::U32
            .encode((u64::from(u32::MAX) + 1).into())
            .is_err());
        assert!(IntType::U32.encode((-1).into()).is_err());
        assert_eq!(IntType::U128.encode(u128::MAX.into()).unwrap(), u128::MAX);
    }

    #[test]
    fn signed_is_offset_binary_and_order_preserving() {
        let encode = |v: i64| IntType::I64.encode(v.into()).unwrap();
        assert_eq!(encode(i64::MIN), 0);
        assert_eq!(encode(-1), (1u128 << 63) - 1);
        assert_eq!(encode(0), 1u128 << 63);
        assert_eq!(encode(i64::MAX), (1u128 << 64) - 1);
        assert!(encode(-5) < encode(-4) && encode(-1) < encode(0) && encode(0) < encode(1));
        assert!(IntType::I64.encode((1i128 << 63).into()).is_err());
        assert!(IntType::I64.encode((-(1i128 << 63) - 1).into()).is_err());
        assert_eq!(IntType::I128.encode(i128::MIN.into()).unwrap(), 0);
        assert_eq!(IntType::I128.encode(i128::MAX.into()).unwrap(), u128::MAX);
        assert!(IntType::I128.encode(u128::MAX.into()).is_err());
    }

    #[test]
    fn limbs_are_little_endian_sixteen_bit() {
        assert_eq!(IntType::U64.limbs(0x0004_0003_0002_0001), vec![1, 2, 3, 4]);
        assert_eq!(IntType::U32.limbs(0xFFFF_0000), vec![0, 0xFFFF]);
        assert_eq!(IntType::U128.limbs(u128::MAX).len(), 8);
    }

    #[test]
    fn parses_decimal_strings_strictly() {
        assert_eq!("-5".parse::<Number>().unwrap(), Number::from(-5i32));
        assert!("-0".parse::<Number>().is_ok());
        assert!("340282366920938463463374607431768211456"
            .parse::<Number>()
            .is_err());
        assert!("-170141183460469231731687303715884105729"
            .parse::<Number>()
            .is_err());
        assert!("1.5".parse::<Number>().is_err());
        assert!("".parse::<Number>().is_err());
    }
}
