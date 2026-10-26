//! Lowering of the arithmetic claims (`Sum`, `Arithmetic`, `Divide`) to the `sum4`/`sum8` and
//! `arith` circuits. Policies are bounded: at most [`MAX_TERMS`] committed terms in a sum and four
//! operands in a product, so the circuit is chosen deterministically from the claim's shape.

use super::claim::{Op, Operand};
use super::commit::{Commitment, DIGEST_ELEMENTS};
use super::int::{IntType, Number};
use super::statement::{
    array, common_type, digest, elements, scalar, signed, Field, Slot, Statement,
};
use crate::{Result, ZkError};
use zk_groth16::Fr;

/// The most committed terms one sum can combine (the larger `sum8` circuit).
pub const MAX_TERMS: usize = 8;
const SMALL_TERMS: usize = 4;
const ZERO_DIGEST: [u64; 8] = [0; 8];

/// A public constant must be a non-negative amount that fits the width of the committed type, so
/// the constant folded into the sum can never exceed the limbs reserved for it.
pub(super) fn amount(ty: IntType, name: &str, number: Number) -> Result<u128> {
    IntType::new(ty.width, false).encode(number).map_err(|_| {
        ZkError::Predicate(format!(
            "{name} {number} is not an amount of {} bits",
            ty.width.bits()
        ))
    })
}

/// `amount + count * 2^(w-1)` as `limbs + 1` canonical 16-bit limbs. The second term is the public
/// offset of `count` signed terms (zero for unsigned types).
fn offset_total(ty: IntType, amount: u128, count: usize) -> Vec<u64> {
    let top = ty.width.limbs();
    let mut limbs = ty.limbs(amount);
    limbs.push(0);
    if ty.signed {
        limbs[top - 1] += count as u64 * 32768;
    }
    let mut carry = 0;
    for limb in limbs.iter_mut().skip(top - 1) {
        let total = *limb + carry;
        *limb = total & 0xFFFF;
        carry = total >> 16;
    }
    limbs
}

fn flags(prefix_len: usize, count: usize, capacity: usize) -> Vec<u64> {
    (0..capacity)
        .map(|i| u64::from(i >= prefix_len && i < prefix_len + count))
        .collect()
}

pub(super) fn sum(
    plus: &[Commitment],
    minus: &[Commitment],
    plus_constant: Number,
    minus_constant: Number,
    op: Op,
) -> Result<Statement> {
    let terms: Vec<Commitment> = plus.iter().chain(minus).copied().collect();
    if terms.len() > MAX_TERMS {
        return Err(ZkError::Predicate(format!(
            "a sum combines at most {MAX_TERMS} committed values, got {}",
            terms.len()
        )));
    }
    let ty = common_type(&terms)?;
    let capacity = if terms.len() <= SMALL_TERMS {
        SMALL_TERMS
    } else {
        MAX_TERMS
    };
    let plus_total = offset_total(ty, amount(ty, "plus constant", plus_constant)?, minus.len());
    let minus_total = offset_total(
        ty,
        amount(ty, "minus constant", minus_constant)?,
        plus.len(),
    );
    let mut commitments: Vec<Fr> = terms.iter().flat_map(Commitment::signals).collect();
    commitments.resize(capacity * DIGEST_ELEMENTS, Fr::from(0u8));
    let [lt, eq, gt] = op.flags();
    let fields = vec![
        elements("commitment", commitments),
        signed(ty),
        array("plus", flags(0, plus.len(), capacity)),
        array("minus", flags(plus.len(), minus.len(), capacity)),
        array("plus_total", plus_total),
        array("minus_total", minus_total),
        scalar("accept_lt", lt),
        scalar("accept_eq", eq),
        scalar("accept_gt", gt),
    ];
    let slots = (0..capacity)
        .map(|i| Slot {
            limb: format!("limb[{i}]"),
            blinding: format!("blinding[{i}]"),
            source: (i < terms.len()).then_some(i),
        })
        .collect();
    Ok(Statement::new(
        format!("sum{capacity}_{}", ty.width.bits()),
        ty,
        slots,
        terms,
        fields,
    ))
}

/// Per-operand public input names (commitment digest, public flag, public limbs) and private
/// signal prefix, in the circuit's declaration order `x, y, z, t`.
const OPERANDS: [[&str; 4]; 4] = [
    ["x_commitment", "x_is_public", "x_public", "x_"],
    ["y_commitment", "y_is_public", "y_public", "y_"],
    ["z_commitment", "z_is_public", "z_public", "z_"],
    ["t_commitment", "t_is_public", "t_public", "t_"],
];

/// The public inputs and witness slot of one operand. `index` is its position among the
/// committed operands in claim order.
fn operand_fields(
    names: &[&'static str; 4],
    operand: Operand,
    ty: IntType,
    index: usize,
) -> Result<(Vec<Field>, Slot)> {
    match operand {
        Operand::Committed(commitment) => Ok((
            vec![
                digest(names[0], &commitment),
                scalar(names[1], 0),
                array(names[2], vec![0; ty.width.limbs()]),
            ],
            Slot::prefixed(names[3], Some(index)),
        )),
        Operand::Public(number) => Ok((
            vec![
                array(names[0], ZERO_DIGEST.to_vec()),
                scalar(names[1], 1),
                array(names[2], ty.limbs(ty.encode(number)?)),
            ],
            Slot::prefixed(names[3], None),
        )),
    }
}

/// `operands` are in circuit order; `claim_order[i]` is where operand `i` stands in the claim, so
/// openings are supplied in the order the developer wrote the operands.
fn arith_statement(
    operands: [Operand; 4],
    claim_order: [usize; 4],
    op: Op,
    divide: bool,
) -> Result<Statement> {
    let committed_at = |position: usize| {
        let circuit = claim_order.iter().position(|p| *p == position)?;
        match operands[circuit] {
            Operand::Committed(c) => Some(c),
            Operand::Public(_) => None,
        }
    };
    let committed: Vec<Commitment> = (0..4).filter_map(committed_at).collect();
    let ty = common_type(&committed)?;
    let mut fields = Vec::new();
    let mut slots = Vec::new();
    for ((operand, names), position) in operands.into_iter().zip(&OPERANDS).zip(claim_order) {
        let index = (0..position).filter(|p| committed_at(*p).is_some()).count();
        let (mut operand_fields, slot) = operand_fields(names, operand, ty, index)?;
        fields.append(&mut operand_fields);
        slots.push(slot);
    }
    let [lt, eq, gt] = op.flags();
    fields.extend([
        signed(ty),
        scalar("accept_lt", lt),
        scalar("accept_eq", eq),
        scalar("accept_gt", gt),
        scalar("divide", u64::from(divide)),
    ]);
    Ok(Statement::new(
        format!("arith_{}", ty.width.bits()),
        ty,
        slots,
        committed,
        fields,
    ))
}

pub(super) fn multiply_add(
    x: Operand,
    y: Operand,
    z: Operand,
    t: Operand,
    op: Op,
) -> Result<Statement> {
    arith_statement([x, y, z, t], [0, 1, 2, 3], op, false)
}

/// The circuit's operand order is `quotient, divisor, remainder, dividend`.
pub(super) fn divide(
    dividend: Operand,
    divisor: Operand,
    quotient: Operand,
    remainder: Operand,
) -> Result<Statement> {
    arith_statement(
        [quotient, divisor, remainder, dividend],
        [2, 1, 3, 0],
        Op::Eq,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::claim::Predicate;

    fn commit(ty: IntType, value: i64) -> Commitment {
        Commitment::commit_with_blinding(ty, value, [3; 8])
            .unwrap()
            .0
    }

    #[test]
    fn sums_pick_the_smallest_circuit_that_holds_the_terms() {
        let c = commit(IntType::U64, 1);
        let circuit = |terms: usize| {
            Predicate::sum_equals(vec![c; terms], c)
                .statement()
                .map(|s| s.circuit().to_owned())
        };
        assert_eq!(circuit(3).unwrap(), "sum4_64");
        assert_eq!(circuit(4).unwrap(), "sum8_64", "the total is a fifth term");
        assert_eq!(circuit(7).unwrap(), "sum8_64");
        assert!(circuit(8).is_err(), "nine terms exceed the bound");
        assert!(Predicate::sum_equals(Vec::new(), c).statement().is_ok());
        assert!(Predicate::total_compare(Vec::new(), Op::Ge, 0)
            .statement()
            .is_err());
    }

    #[test]
    fn signed_offsets_and_constants_are_folded_into_exact_limbs() {
        let c = commit(IntType::I32, -1);
        let statement = Predicate::sum(vec![c, c], 5, Op::Eq, vec![c], 7)
            .statement()
            .unwrap();
        let inputs = statement.public_inputs();
        let tail = &inputs[inputs.len() - 3 - 6..inputs.len() - 3];
        // plus_total = 5 + 1 * 2^31, minus_total = 7 + 2 * 2^31 = 2^32 + 7 (three limbs each).
        assert_eq!(tail, &[5, 0x8000, 0, 7, 0, 1].map(Fr::from));
        assert!(Predicate::sum(vec![c], -1, Op::Eq, vec![c], 0)
            .statement()
            .is_err());
        assert!(
            Predicate::sum(vec![c], u64::MAX, Op::Eq, vec![c], 0)
                .statement()
                .is_err(),
            "an amount wider than the type cannot be folded"
        );
    }

    #[test]
    fn fees_plus_burn_overflow_is_an_error_not_a_wrap() {
        let c = commit(IntType::U128, 1);
        assert!(Predicate::conserve_with_supply(vec![c], vec![c], u128::MAX, 0, 1).is_err());
        assert!(Predicate::conserve_with_supply(vec![c], vec![c], 1, 2, 3).is_ok());
    }

    #[test]
    fn products_need_one_committed_operand_and_one_type() {
        let c = commit(IntType::U32, 2);
        assert!(Predicate::multiply(3, 4, 12).statement().is_err());
        assert!(Predicate::multiply(c, 4, 8).statement().is_ok());
        let other = commit(IntType::I32, 2);
        assert!(Predicate::multiply(c, other, 8).statement().is_err());
        assert!(Predicate::multiply(c, 1u64 << 40, 8).statement().is_err());
        let statement = Predicate::divide(c, 5, c, 1).statement().unwrap();
        assert_eq!(statement.circuit(), "arith_32");
        assert_eq!(statement.committed().len(), 2);
    }

    #[test]
    fn offset_total_carries_across_limbs() {
        let total = offset_total(IntType::I32, 0xFFFF_FFFF, 8);
        // 2^32 - 1 + 8 * 2^31 = 5 * 2^32 - 1
        assert_eq!(total, vec![0xFFFF, 0xFFFF, 4]);
        assert_eq!(
            offset_total(IntType::U32, 0xFFFF_FFFF, 8),
            vec![0xFFFF, 0xFFFF, 0]
        );
    }
}
