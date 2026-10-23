//! Claims: the public statements a prover proves and a verifier checks.
//!
//! A [`Predicate`] is data (serializable to JSON); it names no secret. [`Predicate::statement`]
//! (see `statement.rs`) turns it into the approved circuit name and the exact public inputs that
//! circuit is verified against, so the statement the verifier trusts is derived from the claim,
//! never from the proof.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::commit::Commitment;
use super::int::Number;
use super::set::SetCommitment;
use crate::{Result, ZkError};

/// Comparison operator, realised by the public acceptance flags `(lt, eq, gt)` of the circuits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

impl Op {
    pub(super) fn flags(self) -> [u64; 3] {
        match self {
            Self::Lt => [1, 0, 0],
            Self::Le => [1, 1, 0],
            Self::Gt => [0, 0, 1],
            Self::Ge => [0, 1, 1],
            Self::Eq => [0, 1, 0],
            Self::Ne => [1, 0, 1],
        }
    }

    /// Whether `left op right` holds, given how `left` orders against `right`.
    pub(super) fn accepts(self, ordering: Ordering) -> bool {
        let flags = self.flags();
        flags[match ordering {
            Ordering::Less => 0,
            Ordering::Equal => 1,
            Ordering::Greater => 2,
        }] == 1
    }
}

/// One operand of an arithmetic claim: a number everybody knows, or the value behind a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Public(Number),
    Committed(Commitment),
}

impl From<Commitment> for Operand {
    fn from(commitment: Commitment) -> Self {
        Self::Committed(commitment)
    }
}

macro_rules! public_operands {
    ($($t:ty),*) => {$(
        impl From<$t> for Operand {
            fn from(value: $t) -> Self {
                Self::Public(Number::from(value))
            }
        }
    )*};
}

public_operands!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// JSON form: a commitment is `type:hex...`, a public number is a decimal string.
impl Serialize for Operand {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Public(number) => serializer.collect_str(number),
            Self::Committed(commitment) => serializer.serialize_str(&commitment.to_text()),
        }
    }
}

impl<'de> Deserialize<'de> for Operand {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let operand = if text.contains(':') {
            Commitment::from_text(&text).map(Self::Committed)
        } else {
            text.parse().map(Self::Public)
        };
        operand.map_err(serde::de::Error::custom)
    }
}

/// What is being claimed about committed integers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Predicate {
    /// The prover knows the value and blinding behind `commitment`.
    Opens { commitment: Commitment },
    /// The committed value `op` a public bound.
    Compare {
        commitment: Commitment,
        op: Op,
        bound: Number,
    },
    /// `lo (<|<=) value (<|<=) hi`, each end inclusive when its flag is set.
    Range {
        commitment: Commitment,
        lo: Number,
        hi: Number,
        lo_inclusive: bool,
        hi_inclusive: bool,
    },
    /// `left op right` for two commitments opened by the same prover.
    CompareCommitted {
        left: Commitment,
        right: Commitment,
        op: Op,
    },
    /// `sum(plus) + plus_constant  op  sum(minus) + minus_constant` on exact integers, over at most
    /// eight committed values of one type and two non-negative public constants.
    Sum {
        plus: Vec<Commitment>,
        minus: Vec<Commitment>,
        #[serde(default)]
        plus_constant: Number,
        #[serde(default)]
        minus_constant: Number,
        op: Op,
    },
    /// `x * y + z  op  t` on exact integers; each operand is public or committed.
    Arithmetic {
        x: Operand,
        y: Operand,
        z: Operand,
        t: Operand,
        op: Op,
    },
    /// Euclidean division: `dividend = quotient * divisor + remainder`, `divisor > 0` and
    /// `0 <= remainder < divisor`.
    Divide {
        dividend: Operand,
        divisor: Operand,
        quotient: Operand,
        remainder: Operand,
    },
    /// The committed value is a member of the published set.
    Member {
        commitment: Commitment,
        set: SetCommitment,
    },
    /// The committed value is not a member of the published set.
    Absent {
        commitment: Commitment,
        set: SetCommitment,
    },
}

impl Predicate {
    pub fn opens(commitment: Commitment) -> Self {
        Self::Opens { commitment }
    }

    pub fn compare(commitment: Commitment, op: Op, bound: impl Into<Number>) -> Self {
        Self::Compare {
            commitment,
            op,
            bound: bound.into(),
        }
    }

    pub fn at_least(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Ge, bound)
    }

    pub fn at_most(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Le, bound)
    }

    pub fn greater_than(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Gt, bound)
    }

    pub fn less_than(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Lt, bound)
    }

    pub fn equals(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Eq, bound)
    }

    pub fn not_equals(commitment: Commitment, bound: impl Into<Number>) -> Self {
        Self::compare(commitment, Op::Ne, bound)
    }

    /// `lo <= value <= hi`.
    pub fn in_range(commitment: Commitment, lo: impl Into<Number>, hi: impl Into<Number>) -> Self {
        Self::in_range_with(commitment, lo, hi, true, true)
    }

    pub fn in_range_with(
        commitment: Commitment,
        lo: impl Into<Number>,
        hi: impl Into<Number>,
        lo_inclusive: bool,
        hi_inclusive: bool,
    ) -> Self {
        Self::Range {
            commitment,
            lo: lo.into(),
            hi: hi.into(),
            lo_inclusive,
            hi_inclusive,
        }
    }

    pub fn compare_committed(left: Commitment, op: Op, right: Commitment) -> Self {
        Self::CompareCommitted { left, right, op }
    }

    /// `sum(plus) + plus_constant  op  sum(minus) + minus_constant`.
    pub fn sum(
        plus: Vec<Commitment>,
        plus_constant: impl Into<Number>,
        op: Op,
        minus: Vec<Commitment>,
        minus_constant: impl Into<Number>,
    ) -> Self {
        Self::Sum {
            plus,
            minus,
            plus_constant: plus_constant.into(),
            minus_constant: minus_constant.into(),
            op,
        }
    }

    /// Conservation: `sum(inputs) == sum(outputs) + fees`.
    pub fn conserve(
        inputs: Vec<Commitment>,
        outputs: Vec<Commitment>,
        fees: impl Into<Number>,
    ) -> Self {
        Self::sum(inputs, 0, Op::Eq, outputs, fees)
    }

    /// Conservation with authorised supply changes:
    /// `sum(inputs) + minted == sum(outputs) + fees + burned`. Fails if `fees + burned` overflows.
    pub fn conserve_with_supply(
        inputs: Vec<Commitment>,
        outputs: Vec<Commitment>,
        fees: impl Into<Number>,
        minted: impl Into<Number>,
        burned: impl Into<Number>,
    ) -> Result<Self> {
        let leaving = fees
            .into()
            .checked_add_unsigned(burned.into())
            .ok_or_else(|| {
                ZkError::Predicate("fees + burned must be non-negative and fit u128".into())
            })?;
        Ok(Self::sum(inputs, minted, Op::Eq, outputs, leaving))
    }

    /// `a + b == total`.
    pub fn add(a: Commitment, b: Commitment, total: Commitment) -> Self {
        Self::sum(vec![a, b], 0, Op::Eq, vec![total], 0)
    }

    /// `a - b == difference`.
    pub fn subtract(a: Commitment, b: Commitment, difference: Commitment) -> Self {
        Self::sum(vec![a], 0, Op::Eq, vec![b, difference], 0)
    }

    /// `sum(terms) == total`.
    pub fn sum_equals(terms: Vec<Commitment>, total: Commitment) -> Self {
        Self::sum(terms, 0, Op::Eq, vec![total], 0)
    }

    /// `sum(terms) op bound`: a balance, inventory or quantity invariant.
    pub fn total_compare(terms: Vec<Commitment>, op: Op, bound: impl Into<Number>) -> Self {
        Self::sum(terms, 0, op, Vec::new(), bound)
    }

    /// `x * y + z  op  t`.
    pub fn arithmetic(
        x: impl Into<Operand>,
        y: impl Into<Operand>,
        z: impl Into<Operand>,
        op: Op,
        t: impl Into<Operand>,
    ) -> Self {
        Self::Arithmetic {
            x: x.into(),
            y: y.into(),
            z: z.into(),
            t: t.into(),
            op,
        }
    }

    /// `x * y == product` with no overflow (the exact product must equal `product`).
    pub fn multiply(
        x: impl Into<Operand>,
        y: impl Into<Operand>,
        product: impl Into<Operand>,
    ) -> Self {
        Self::arithmetic(x, y, 0u8, Op::Eq, product)
    }

    /// `dividend = quotient * divisor + remainder`, `divisor > 0`, `0 <= remainder < divisor`.
    pub fn divide(
        dividend: impl Into<Operand>,
        divisor: impl Into<Operand>,
        quotient: impl Into<Operand>,
        remainder: impl Into<Operand>,
    ) -> Self {
        Self::Divide {
            dividend: dividend.into(),
            divisor: divisor.into(),
            quotient: quotient.into(),
            remainder: remainder.into(),
        }
    }

    /// The committed value is in `set` (prove with a path from `SetTree::member_path`).
    pub fn member_of(commitment: Commitment, set: SetCommitment) -> Self {
        Self::Member { commitment, set }
    }

    /// The committed value is not in `set` (prove with a path from `SetTree::absence_path`).
    pub fn not_member_of(commitment: Commitment, set: SetCommitment) -> Self {
        Self::Absent { commitment, set }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("claims always serialize")
    }

    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))
    }
}
