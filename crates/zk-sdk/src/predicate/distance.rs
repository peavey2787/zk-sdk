//! Lowering of the `Distance` claim to the `distance` circuits: a committed point against a public
//! centre and radius. The circuit compares exact squared distances, so the verifier supplies the
//! squared radius (`2L` limbs) and no square root, rounding or wrapping is involved.

use super::arithmetic::amount;
use super::claim::Op;
use super::commit::Commitment;
use super::exact::Int;
use super::int::Number;
use super::statement::{array, common_type, digest, limbs, scalar, signed, Slot, Statement};
use crate::{Result, ZkError};

pub(super) fn statement(
    x: &Commitment,
    y: &Commitment,
    center: (Number, Number),
    op: Op,
    radius: Number,
) -> Result<Statement> {
    let committed = vec![*x, *y];
    let ty = common_type(&committed)?;
    let radius = Int::from(Number::from(amount(ty, "radius", radius)?));
    let radius_sq = radius
        .mul(&radius)
        .limbs(2 * ty.width.limbs())
        .ok_or_else(|| ZkError::Predicate("the squared radius exceeds the circuit".into()))?;
    let [lt, eq, gt] = op.flags();
    let fields = vec![
        digest("x_commitment", x),
        digest("y_commitment", y),
        signed(ty),
        limbs("center_x", ty, center.0)?,
        limbs("center_y", ty, center.1)?,
        scalar("accept_lt", lt),
        scalar("accept_eq", eq),
        scalar("accept_gt", gt),
        array("radius_sq", radius_sq),
    ];
    let slots = vec![Slot::prefixed("x_", Some(0)), Slot::prefixed("y_", Some(1))];
    Ok(Statement::new(
        format!("distance_{}", ty.width.bits()),
        ty,
        slots,
        committed,
        fields,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::claim::Predicate;
    use crate::predicate::int::IntType;

    fn point(ty: IntType) -> (Commitment, Commitment) {
        let commit = |v: i8| Commitment::commit_with_blinding(ty, v, [2; 8]).unwrap().0;
        (commit(1), commit(2))
    }

    #[test]
    fn the_squared_radius_fills_twice_the_limbs_and_never_wraps() {
        let (x, y) = point(IntType::U32);
        let claim = Predicate::within_distance(x, y, (0u8, 0u8), u32::MAX);
        let inputs = claim.statement().unwrap().public_inputs();
        // 8 + 8 digest words, signed, two centres (2 limbs each), three flags, then radius^2.
        let radius_sq = &inputs[inputs.len() - 4..];
        // (2^32 - 1)^2 = 2^64 - 2^33 + 1
        assert_eq!(radius_sq, &[1, 0, 0xFFFE, 0xFFFF].map(zk_groth16::Fr::from));
    }

    #[test]
    fn centre_radius_and_types_must_fit() {
        let (x, y) = point(IntType::U32);
        assert!(Predicate::within_distance(x, y, (0u8, 0u8), 5u8)
            .statement()
            .is_ok());
        assert!(
            Predicate::within_distance(x, y, (-1, 0), 5u8)
                .statement()
                .is_err(),
            "an unsigned centre cannot be negative"
        );
        assert!(
            Predicate::within_distance(x, y, (0u8, 0u8), -5)
                .statement()
                .is_err(),
            "a radius is a non-negative amount"
        );
        assert!(Predicate::within_distance(x, y, (0u8, 0u8), 1u64 << 32)
            .statement()
            .is_err());
        let (_, other) = point(IntType::I32);
        assert!(Predicate::within_distance(x, other, (0u8, 0u8), 5u8)
            .statement()
            .is_err());
    }

    #[test]
    fn the_circuit_follows_the_type_width() {
        let (x, y) = point(IntType::I128);
        let statement = Predicate::beyond_distance(x, y, (-3, 4), 9u8)
            .statement()
            .unwrap();
        assert_eq!(statement.circuit(), "distance_128");
        assert_eq!(statement.committed().len(), 2);
    }
}
