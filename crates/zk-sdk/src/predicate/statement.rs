//! Lowering a claim to its circuit statement: the approved circuit name, the exact public inputs it
//! is verified against, and where each private opening goes. The verifier derives all of this from
//! the claim it trusts, never from the proof.

use super::arithmetic;
use super::claim::Predicate;
use super::commit::Commitment;
use super::credential;
use super::distance;
use super::int::{IntType, Number};
use super::scheme::Scheme;
use super::set::SetCommitment;
use crate::{Result, ZkError};
use zk_groth16::Fr;

/// One named circuit input: a scalar signal, or an array signal addressed as `name[i]`. Values are
/// BN254 scalars, which hold every KoalaBear element too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub name: &'static str,
    pub values: Vec<Fr>,
    pub array: bool,
}

pub(super) fn scalar(name: &'static str, value: u64) -> Field {
    Field {
        name,
        values: vec![Fr::from(value)],
        array: false,
    }
}

pub(super) fn array(name: &'static str, values: Vec<u64>) -> Field {
    Field {
        name,
        values: values.into_iter().map(Fr::from).collect(),
        array: true,
    }
}

/// An array of signals already in field form.
pub(super) fn elements(name: &'static str, values: Vec<Fr>) -> Field {
    Field {
        name,
        values,
        array: true,
    }
}

pub(super) fn digest(name: &'static str, commitment: &Commitment) -> Field {
    elements(name, commitment.signals())
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
/// (Schemes are checked once per statement, in [`Predicate::statement`].)
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

    pub(super) fn with_path(mut self, shape: PathShape) -> Self {
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

    /// The proof system of this statement's commitments (see [`Predicate::statement`]).
    pub fn scheme(&self) -> Scheme {
        self.committed
            .first()
            .map_or(Scheme::SpartanWhir, Commitment::scheme)
    }

    /// Every commitment must share one scheme, and a Groth16 statement must name an approved circuit.
    fn checked_scheme(self) -> Result<Self> {
        let scheme = self.scheme();
        if let Some(other) = self.committed.iter().find(|c| c.scheme() != scheme) {
            return Err(ZkError::Predicate(format!(
                "cannot combine {scheme} and {} commitments in one claim",
                other.scheme()
            )));
        }
        if scheme == Scheme::Groth16 && !zk_groth16::circuits().any(|c| c == self.circuit) {
            return Err(ZkError::Predicate(format!(
                "`{}` is not an approved groth16 circuit",
                self.circuit
            )));
        }
        Ok(self)
    }

    /// The flat public input vector the verifier checks the proof against.
    pub fn public_inputs(&self) -> Vec<Fr> {
        self.fields
            .iter()
            .flat_map(|f| f.values.iter().copied())
            .collect()
    }
}

impl Predicate {
    /// The approved circuit and public inputs for this claim. Fails when a number does not fit the
    /// committed type, committed values disagree on type or scheme, a collection exceeds its bound,
    /// or the commitments' scheme has no circuit for this family.
    pub fn statement(&self) -> Result<Statement> {
        self.lower()?.checked_scheme()
    }

    fn lower(&self) -> Result<Statement> {
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
            Self::Credential {
                attribute,
                serial,
                expiry,
                issuer,
                now,
            } => credential::statement(attribute, serial, expiry, issuer, *now),
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

/// Fails unless a published structure (`what`, of `scheme`) belongs to `commitment`'s scheme.
pub(super) fn same_scheme(commitment: &Commitment, scheme: Scheme, what: &str) -> Result<()> {
    if commitment.scheme() == scheme {
        Ok(())
    } else {
        Err(ZkError::Predicate(format!(
            "a {} commitment cannot be checked against a {scheme} {what}",
            commitment.scheme()
        )))
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
    same_scheme(commitment, set.scheme(), "set")?;
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
            elements("root", root.signals()),
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
        assert_eq!(
            &inputs[8..12],
            &[0, 0, 1, 1].map(Fr::from),
            "unsigned, then ge"
        );
        assert_eq!(
            &inputs[12..],
            &[2, 3].map(Fr::from),
            "little-endian 16-bit limbs"
        );
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

    #[test]
    fn groth16_claims_stay_within_their_scheme_and_families() {
        let g = Commitment::commit_in(Scheme::Groth16, IntType::U64, 5u8)
            .unwrap()
            .0;
        let statement = Predicate::at_least(g, 1).statement().unwrap();
        assert_eq!(
            (statement.circuit(), statement.scheme()),
            ("compare_64", Scheme::Groth16)
        );
        assert_eq!(
            statement.public_inputs().len(),
            1 + 1 + 3 + 4,
            "one-element digest"
        );
        let mixed = Predicate::compare_committed(g, Op::Lt, commitment(IntType::U64));
        assert!(mixed.statement().is_err(), "schemes never mix");
        let multiply = Predicate::multiply(g, 2, g).statement().unwrap();
        assert_eq!(
            multiply.circuit(),
            "arith_64",
            "every family has a groth16 circuit"
        );
    }
}
