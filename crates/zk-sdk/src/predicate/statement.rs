//! Lowering a claim to its circuit statement: the approved circuit name, the exact public inputs it
//! is verified against, and where each private opening goes. The verifier derives all of this from
//! the claim it trusts, never from the proof.

use super::arithmetic;
use super::claim::Predicate;
use super::commit::Commitment;
use super::distance;
use super::int::{IntType, Number};
use super::set::SetCommitment;
use crate::{Result, ZkError};

/// One named circuit input: a scalar signal, or an array signal addressed as `name[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub name: &'static str,
    pub values: Vec<u64>,
    pub array: bool,
}

pub(super) fn scalar(name: &'static str, value: u64) -> Field {
    Field {
        name,
        values: vec![value],
        array: false,
    }
}

pub(super) fn array(name: &'static str, values: Vec<u64>) -> Field {
    Field {
        name,
        values,
        array: true,
    }
}

pub(super) fn digest(name: &'static str, commitment: &Commitment) -> Field {
    array(
        name,
        commitment.digest().iter().map(|d| u64::from(*d)).collect(),
    )
}

pub(super) fn signed(ty: IntType) -> Field {
    scalar("signed", u64::from(ty.signed))
}

pub(super) fn limbs(name: &'static str, ty: IntType, number: Number) -> Result<Field> {
    Ok(array(name, ty.limbs(ty.encode(number)?)))
}

/// Where a circuit's private opening signals are and which witness opening feeds them. A slot with
/// no `source` is an unused position of a fixed-capacity circuit and is filled with zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Slot {
    pub limb: String,
    pub blinding: String,
    pub source: Option<usize>,
}

impl Slot {
    /// The slot whose signals are `<prefix>limb` and `<prefix>blinding`.
    pub(super) fn prefixed(prefix: &str, source: Option<usize>) -> Self {
        Self {
            limb: format!("{prefix}limb"),
            blinding: format!("{prefix}blinding"),
            source,
        }
    }
}

/// The type shared by every commitment, or an error when they disagree or there are none.
pub(super) fn common_type(commitments: &[Commitment]) -> Result<IntType> {
    let first = commitments
        .first()
        .ok_or_else(|| ZkError::Predicate("a claim needs at least one committed value".into()))?;
    match commitments.iter().find(|c| c.ty() != first.ty()) {
        Some(other) => Err(ZkError::Predicate(format!(
            "cannot combine {} with {}",
            first.ty(),
            other.ty()
        ))),
        None => Ok(first.ty()),
    }
}

/// A claim lowered to its circuit: the public inputs by circuit signal name, in declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    circuit: String,
    ty: IntType,
    slots: Vec<Slot>,
    committed: Vec<Commitment>,
    fields: Vec<Field>,
    path: Option<PathShape>,
}

/// The private Merkle path a set claim's circuit also needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PathShape {
    pub absent: bool,
    pub depth: usize,
}

impl Statement {
    pub(super) fn new(
        circuit: String,
        ty: IntType,
        slots: Vec<Slot>,
        committed: Vec<Commitment>,
        fields: Vec<Field>,
    ) -> Self {
        Self {
            circuit,
            ty,
            slots,
            committed,
            fields,
            path: None,
        }
    }

    /// A statement over `committed` openings whose slots are named `<prefix>limb`/`<prefix>blinding`.
    fn prefixed(
        family: &str,
        committed: Vec<Commitment>,
        prefixes: &[&str],
        fields: Vec<Field>,
    ) -> Result<Self> {
        let ty = common_type(&committed)?;
        let slots = prefixes
            .iter()
            .enumerate()
            .map(|(i, prefix)| Slot::prefixed(prefix, Some(i)))
            .collect();
        Ok(Self::new(
            format!("{family}_{}", ty.width.bits()),
            ty,
            slots,
            committed,
            fields,
        ))
    }

    fn with_path(mut self, shape: PathShape) -> Self {
        self.path = Some(shape);
        self
    }

    pub(super) fn path(&self) -> Option<PathShape> {
        self.path
    }

    pub fn circuit(&self) -> &str {
        &self.circuit
    }

    pub fn ty(&self) -> IntType {
        self.ty
    }

    /// The commitments whose openings the prover must supply, in witness order.
    pub fn committed(&self) -> &[Commitment] {
        &self.committed
    }

    pub(super) fn slots(&self) -> &[Slot] {
        &self.slots
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

impl Predicate {
    /// The approved circuit and public inputs for this claim. Fails when a number does not fit the
    /// committed type, committed values disagree on type, or a collection exceeds its bound.
    pub fn statement(&self) -> Result<Statement> {
        match self {
            Self::Opens { commitment } => Statement::prefixed(
                "open",
                vec![*commitment],
                &[""],
                vec![digest("commitment", commitment), signed(commitment.ty())],
            ),
            Self::Compare {
                commitment,
                op,
                bound,
            } => {
                let ty = commitment.ty();
                let [lt, eq, gt] = op.flags();
                Statement::prefixed(
                    "compare",
                    vec![*commitment],
                    &[""],
                    vec![
                        digest("commitment", commitment),
                        signed(ty),
                        scalar("accept_lt", lt),
                        scalar("accept_eq", eq),
                        scalar("accept_gt", gt),
                        limbs("bound", ty, *bound)?,
                    ],
                )
            }
            Self::Range {
                commitment,
                lo,
                hi,
                lo_inclusive,
                hi_inclusive,
            } => {
                let ty = commitment.ty();
                Statement::prefixed(
                    "range",
                    vec![*commitment],
                    &[""],
                    vec![
                        digest("commitment", commitment),
                        signed(ty),
                        scalar("lo_inclusive", u64::from(*lo_inclusive)),
                        scalar("hi_inclusive", u64::from(*hi_inclusive)),
                        limbs("lo", ty, *lo)?,
                        limbs("hi", ty, *hi)?,
                    ],
                )
            }
            Self::CompareCommitted { left, right, op } => {
                let ty = common_type(&[*left, *right])?;
                let [lt, eq, gt] = op.flags();
                Statement::prefixed(
                    "compare_committed",
                    vec![*left, *right],
                    &["left_", "right_"],
                    vec![
                        digest("left", left),
                        digest("right", right),
                        signed(ty),
                        scalar("accept_lt", lt),
                        scalar("accept_eq", eq),
                        scalar("accept_gt", gt),
                    ],
                )
            }
            Self::Sum {
                plus,
                minus,
                plus_constant,
                minus_constant,
                op,
            } => arithmetic::sum(plus, minus, *plus_constant, *minus_constant, *op),
            Self::Arithmetic { x, y, z, t, op } => arithmetic::multiply_add(*x, *y, *z, *t, *op),
            Self::Divide {
                dividend,
                divisor,
                quotient,
                remainder,
            } => arithmetic::divide(*dividend, *divisor, *quotient, *remainder),
            Self::Member { commitment, set } => set_statement(commitment, set, false),
            Self::Absent { commitment, set } => set_statement(commitment, set, true),
            Self::InAnyRange { commitment, ranges } => any_range_statement(commitment, ranges),
            Self::Distance {
                x,
                y,
                center_x,
                center_y,
                op,
                radius,
            } => distance::statement(x, y, (*center_x, *center_y), *op, *radius),
        }
    }
}

/// The most intervals one `InAnyRange` claim can union (the `anyrange` circuit's slots).
pub const MAX_RANGES: usize = 4;

fn any_range_statement(commitment: &Commitment, ranges: &[[Number; 2]]) -> Result<Statement> {
    if ranges.is_empty() || ranges.len() > MAX_RANGES {
        return Err(ZkError::Predicate(format!(
            "a union takes 1 to {MAX_RANGES} intervals, got {}",
            ranges.len()
        )));
    }
    let ty = commitment.ty();
    let mut bounds = [Vec::new(), Vec::new()];
    for slot in 0..MAX_RANGES {
        for (end, column) in bounds.iter_mut().enumerate() {
            column.extend(match ranges.get(slot) {
                Some(range) => ty.limbs(ty.encode(range[end])?),
                None => vec![0; ty.width.limbs()],
            });
        }
    }
    let [lo, hi] = bounds;
    let enabled = (0..MAX_RANGES).map(|slot| u64::from(slot < ranges.len()));
    Statement::prefixed(
        "anyrange",
        vec![*commitment],
        &[""],
        vec![
            digest("commitment", commitment),
            signed(ty),
            array("enabled", enabled.collect()),
            array("lo", lo),
            array("hi", hi),
        ],
    )
}

fn set_statement(commitment: &Commitment, set: &SetCommitment, absent: bool) -> Result<Statement> {
    let ty = commitment.ty();
    if set.ty() != ty {
        return Err(ZkError::Predicate(format!(
            "a {ty} commitment cannot be tested against a set of {}",
            set.ty()
        )));
    }
    let (family, root) = if absent {
        ("absent", set.gaps())
    } else {
        ("member", set.members())
    };
    let statement = Statement::prefixed(
        &format!("{family}{}", set.depth()),
        vec![*commitment],
        &[""],
        vec![
            digest("commitment", commitment),
            signed(ty),
            array("root", root.iter().map(|w| u64::from(*w)).collect()),
        ],
    )?;
    Ok(statement.with_path(PathShape {
        absent,
        depth: set.depth(),
    }))
}

#[cfg(test)]
mod tests {
    use super::super::claim::Op;
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
            Predicate::conserve(vec![c, c], vec![c], 3),
            Predicate::multiply(c, 6, c),
            Predicate::divide(c, 7, c, 2),
        ] {
            assert_eq!(Predicate::from_json(&claim.to_json()).unwrap(), claim);
        }
        assert!(Predicate::from_json(r#"{"kind":"teleport"}"#).is_err());
        assert!(Predicate::from_json("{}").is_err());
    }
}
