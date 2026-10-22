//! Claims: the public statements a prover proves and a verifier checks.
//!
//! A [`Predicate`] is data (serializable to JSON); it names no secret. [`Predicate::statement`]
//! turns it into the approved circuit name and the exact public inputs that circuit is verified
//! against, so the statement the verifier trusts is derived from the claim, never from the proof.

use serde::{Deserialize, Serialize};

use super::commit::Commitment;
use super::int::{IntType, Number};
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
    fn flags(self) -> [u64; 3] {
        match self {
            Self::Lt => [1, 0, 0],
            Self::Le => [1, 1, 0],
            Self::Gt => [0, 0, 1],
            Self::Ge => [0, 1, 1],
            Self::Eq => [0, 1, 0],
            Self::Ne => [1, 0, 1],
        }
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

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("claims always serialize")
    }

    pub fn from_json(text: &str) -> Result<Self> {
        serde_json::from_str(text).map_err(|e| ZkError::Format(e.to_string()))
    }

    /// The approved circuit and public inputs for this claim. Fails when a bound does not fit the
    /// committed type or two commitments disagree on type.
    pub fn statement(&self) -> Result<Statement> {
        match self {
            Self::Opens { commitment } => Ok(Statement::new(
                "open",
                commitment.ty(),
                &[""],
                vec![digest("commitment", commitment), signed(commitment.ty())],
            )),
            Self::Compare {
                commitment,
                op,
                bound,
            } => {
                let ty = commitment.ty();
                Ok(Statement::new(
                    "compare",
                    ty,
                    &[""],
                    vec![
                        digest("commitment", commitment),
                        signed(ty),
                        scalar("accept_lt", op.flags()[0]),
                        scalar("accept_eq", op.flags()[1]),
                        scalar("accept_gt", op.flags()[2]),
                        limbs("bound", ty, *bound)?,
                    ],
                ))
            }
            Self::Range {
                commitment,
                lo,
                hi,
                lo_inclusive,
                hi_inclusive,
            } => {
                let ty = commitment.ty();
                Ok(Statement::new(
                    "range",
                    ty,
                    &[""],
                    vec![
                        digest("commitment", commitment),
                        signed(ty),
                        scalar("lo_inclusive", u64::from(*lo_inclusive)),
                        scalar("hi_inclusive", u64::from(*hi_inclusive)),
                        limbs("lo", ty, *lo)?,
                        limbs("hi", ty, *hi)?,
                    ],
                ))
            }
            Self::CompareCommitted { left, right, op } => {
                if left.ty() != right.ty() {
                    return Err(ZkError::Predicate(format!(
                        "cannot compare {} with {}",
                        left.ty(),
                        right.ty()
                    )));
                }
                Ok(Statement::new(
                    "compare_committed",
                    left.ty(),
                    &["left_", "right_"],
                    vec![
                        digest("left", left),
                        digest("right", right),
                        signed(left.ty()),
                        scalar("accept_lt", op.flags()[0]),
                        scalar("accept_eq", op.flags()[1]),
                        scalar("accept_gt", op.flags()[2]),
                    ],
                ))
            }
        }
    }
}

/// One named circuit input: a scalar signal, or an array signal addressed as `name[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub name: &'static str,
    pub values: Vec<u64>,
    pub array: bool,
}

fn scalar(name: &'static str, value: u64) -> Field {
    Field {
        name,
        values: vec![value],
        array: false,
    }
}

fn array(name: &'static str, values: Vec<u64>) -> Field {
    Field {
        name,
        values,
        array: true,
    }
}

fn digest(name: &'static str, commitment: &Commitment) -> Field {
    array(
        name,
        commitment.digest().iter().map(|d| u64::from(*d)).collect(),
    )
}

fn signed(ty: IntType) -> Field {
    scalar("signed", u64::from(ty.signed))
}

fn limbs(name: &'static str, ty: IntType, number: Number) -> Result<Field> {
    Ok(array(name, ty.limbs(ty.encode(number)?)))
}

/// A claim lowered to its circuit: the public inputs by circuit signal name, in declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    circuit: String,
    ty: IntType,
    slots: &'static [&'static str],
    fields: Vec<Field>,
}

impl Statement {
    fn new(family: &str, ty: IntType, slots: &'static [&'static str], fields: Vec<Field>) -> Self {
        Self {
            circuit: format!("{family}_{}", ty.width.bits()),
            ty,
            slots,
            fields,
        }
    }

    pub fn circuit(&self) -> &str {
        &self.circuit
    }

    pub fn ty(&self) -> IntType {
        self.ty
    }

    /// Prefixes of the private `limb`/`blinding` signals: one opening per slot.
    pub(super) fn slots(&self) -> &'static [&'static str] {
        self.slots
    }

    pub(super) fn named(&self) -> &[Field] {
        &self.fields
    }

    /// The flat public input vector the verifier checks the proof against.
    pub fn public_inputs(&self) -> Vec<u64> {
        self.fields
            .iter()
            .flat_map(|f| f.values.iter().copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(ty: IntType) -> Commitment {
        Commitment::commit_with_blinding(ty, 1u8, [1; 8]).unwrap().0
    }

    #[test]
    fn statements_pick_circuit_by_family_and_width() {
        let c = commitment(IntType::U64);
        assert_eq!(
            Predicate::at_least(c, 18).statement().unwrap().circuit(),
            "compare_64"
        );
        assert_eq!(
            Predicate::opens(c).statement().unwrap().circuit(),
            "open_64"
        );
        assert_eq!(
            Predicate::in_range(c, 1, 2).statement().unwrap().circuit(),
            "range_64"
        );
        let wide = commitment(IntType::I128);
        let pair = Predicate::compare_committed(wide, Op::Lt, wide);
        assert_eq!(pair.statement().unwrap().circuit(), "compare_committed_128");
    }

    #[test]
    fn public_inputs_follow_circuit_declaration_order() {
        let c = commitment(IntType::U32);
        let inputs = Predicate::at_least(c, 0x0003_0002u32)
            .statement()
            .unwrap()
            .public_inputs();
        assert_eq!(inputs.len(), 8 + 1 + 3 + 2);
        assert_eq!(&inputs[8..12], &[0, 0, 1, 1], "unsigned, then ge = (0,1,1)");
        assert_eq!(&inputs[12..], &[2, 3], "little-endian 16-bit limbs");
    }

    #[test]
    fn operator_flags_are_the_six_comparisons() {
        let flags: Vec<_> = [Op::Lt, Op::Le, Op::Gt, Op::Ge, Op::Eq, Op::Ne]
            .map(Op::flags)
            .to_vec();
        assert_eq!(
            flags,
            [
                [1, 0, 0],
                [1, 1, 0],
                [0, 0, 1],
                [0, 1, 1],
                [0, 1, 0],
                [1, 0, 1]
            ]
        );
    }

    #[test]
    fn out_of_range_bounds_and_mixed_types_are_rejected() {
        let c = commitment(IntType::U32);
        assert!(Predicate::at_least(c, u64::MAX).statement().is_err());
        assert!(Predicate::at_least(c, -1).statement().is_err());
        assert!(Predicate::in_range(c, 0, 1u64 << 32).statement().is_err());
        let mixed = Predicate::compare_committed(c, Op::Eq, commitment(IntType::I32));
        assert!(mixed.statement().is_err());
    }

    #[test]
    fn json_round_trips_and_rejects_unknown_shapes() {
        let c = commitment(IntType::I64);
        for claim in [
            Predicate::opens(c),
            Predicate::not_equals(c, -7),
            Predicate::in_range_with(c, -5, 5, false, true),
            Predicate::compare_committed(c, Op::Ge, c),
        ] {
            assert_eq!(Predicate::from_json(&claim.to_json()).unwrap(), claim);
        }
        assert!(Predicate::from_json(r#"{"kind":"teleport"}"#).is_err());
        assert!(Predicate::from_json("{}").is_err());
    }
}
