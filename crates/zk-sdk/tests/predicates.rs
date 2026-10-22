//! Real full-ZK proofs for the built-in predicate library: positive, boundary, negative, malformed
//! and adversarial. Nothing here is mocked; every success is a Spartan-WHIR proof verified against
//! a statement derived independently from the claim.

use std::sync::OnceLock;

use zk_sdk::predicate::{Commitment, IntType, Op, Predicate, PredicateProof, Predicates};

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(Predicates::new)
}

fn commit(
    ty: IntType,
    value: impl Into<zk_sdk::predicate::Number>,
) -> (Commitment, zk_sdk::predicate::Opening) {
    Commitment::commit(ty, value).unwrap()
}

fn holds(claim: &Predicate, opening: &zk_sdk::predicate::Opening) -> PredicateProof {
    let proof = zk()
        .prove(claim, opening)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    zk().verify(claim, &proof)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    proof
}

fn is_false(claim: &Predicate, opening: &zk_sdk::predicate::Opening) {
    assert!(
        zk().prove(claim, opening).is_err(),
        "a false claim must not be provable: {claim:?}"
    );
}

#[test]
fn age_threshold_end_to_end() {
    let (c, opening) = commit(IntType::U32, 20u32);
    let claim = Predicate::at_least(c, 18);
    let proof = holds(&claim, &opening);
    assert!(
        zk().verify(&Predicate::at_least(c, 21), &proof).is_err(),
        "proof is bound to the bound"
    );
    assert!(
        zk().verify(&Predicate::at_most(c, 18), &proof).is_err(),
        "proof is bound to the operator"
    );
    is_false(&Predicate::at_least(c, 21), &opening);
}

#[test]
fn comparison_operators_at_the_boundary() {
    let (c, opening) = commit(IntType::U32, 18u32);
    for claim in [
        Predicate::at_least(c, 18),
        Predicate::at_most(c, 18),
        Predicate::equals(c, 18),
        Predicate::greater_than(c, 17),
        Predicate::less_than(c, 19),
        Predicate::not_equals(c, 19),
    ] {
        holds(&claim, &opening);
    }
    for claim in [
        Predicate::greater_than(c, 18),
        Predicate::less_than(c, 18),
        Predicate::not_equals(c, 18),
        Predicate::equals(c, 17),
        Predicate::at_least(c, 19),
        Predicate::at_most(c, 17),
    ] {
        is_false(&claim, &opening);
    }
}

#[test]
fn extremes_of_every_width_and_sign() {
    for (ty, min, max) in [
        (IntType::U32, 0i128, i128::from(u32::MAX)),
        (IntType::I32, i128::from(i32::MIN), i128::from(i32::MAX)),
        (IntType::I64, i128::from(i64::MIN), i128::from(i64::MAX)),
        (IntType::I128, i128::MIN, i128::MAX),
    ] {
        let (c_min, o_min) = commit(ty, min);
        let (c_max, o_max) = commit(ty, max);
        holds(&Predicate::equals(c_min, min), &o_min);
        holds(&Predicate::at_most(c_min, min), &o_min);
        holds(&Predicate::at_least(c_max, max), &o_max);
        holds(&Predicate::less_than(c_min, min + 1), &o_min);
        is_false(&Predicate::less_than(c_min, min), &o_min);
        is_false(&Predicate::greater_than(c_max, max), &o_max);
    }
    let (c, o) = commit(IntType::U128, u128::MAX);
    holds(&Predicate::at_least(c, u128::MAX), &o);
    let (c, o) = commit(IntType::U64, u64::MAX);
    holds(&Predicate::greater_than(c, u64::MAX - 1), &o);
}

#[test]
fn signed_values_order_across_zero() {
    let (c, o) = commit(IntType::I64, -5i64);
    holds(&Predicate::less_than(c, 0), &o);
    holds(&Predicate::greater_than(c, -6), &o);
    holds(&Predicate::in_range(c, -10, -1), &o);
    is_false(&Predicate::at_least(c, 0), &o);
}

#[test]
fn ranges_with_inclusive_and_exclusive_ends() {
    let (c, o) = commit(IntType::U64, 10u64);
    holds(&Predicate::in_range(c, 10, 10), &o);
    holds(&Predicate::in_range(c, 0, 100), &o);
    holds(&Predicate::in_range_with(c, 9, 11, false, false), &o);
    is_false(&Predicate::in_range_with(c, 10, 20, false, true), &o);
    is_false(&Predicate::in_range_with(c, 0, 10, true, false), &o);
    is_false(&Predicate::in_range(c, 11, 20), &o);
    is_false(&Predicate::in_range(c, 0, 9), &o);
    is_false(&Predicate::in_range(c, 20, 0), &o);
}

#[test]
fn knowledge_of_a_commitment_opening() {
    let (c, o) = commit(IntType::U64, 123_456_789u64);
    let proof = holds(&Predicate::opens(c), &o);
    let (other, _) = commit(IntType::U64, 123_456_789u64);
    assert!(
        zk().verify(&Predicate::opens(other), &proof).is_err(),
        "a different commitment is a different statement"
    );
}

#[test]
fn committed_to_committed_comparison() {
    let (a, oa) = commit(IntType::I64, -3i64);
    let (b, ob) = commit(IntType::I64, 4i64);
    let claim = Predicate::compare_committed(a, Op::Lt, b);
    let proof = zk().prove(&claim, (oa.clone(), ob.clone())).unwrap();
    zk().verify(&claim, &proof).unwrap();
    assert!(
        zk().verify(&Predicate::compare_committed(b, Op::Lt, a), &proof)
            .is_err(),
        "operands are ordered"
    );
    assert!(zk()
        .prove(
            &Predicate::compare_committed(a, Op::Ge, b),
            (oa.clone(), ob.clone())
        )
        .is_err());
    assert!(
        zk().prove(&claim, (ob, oa)).is_err(),
        "openings must follow the claim's order"
    );
}

#[test]
fn wrong_or_mismatched_openings_are_rejected() {
    let (c, o) = commit(IntType::U32, 20u32);
    let (_, other) = commit(IntType::U32, 20u32);
    let (_, wrong_value) = commit(IntType::U32, 30u32);
    let (_, wrong_type) = commit(IntType::U64, 20u64);
    let claim = Predicate::at_least(c, 18);
    for bad in [&other, &wrong_value, &wrong_type] {
        assert!(zk().prove(&claim, bad).is_err());
    }
    assert!(
        zk().prove(&Predicate::compare_committed(c, Op::Eq, c), &o)
            .is_err(),
        "wrong opening count"
    );
    assert!(
        zk().prove(&Predicate::at_least(c, -1), &o).is_err(),
        "bound does not fit the type"
    );
}

#[test]
fn malformed_and_cross_circuit_proofs_never_verify() {
    let (c, o) = commit(IntType::U32, 20u32);
    let claim = Predicate::at_least(c, 18);
    let proof = holds(&claim, &o);
    let bytes = proof.as_bytes();
    assert!(zk()
        .verify(&claim, &PredicateProof::from_bytes(Vec::new()))
        .is_err());
    assert!(zk()
        .verify(
            &claim,
            &PredicateProof::from_bytes(bytes[..bytes.len() - 1].to_vec())
        )
        .is_err());
    for position in [0, bytes.len() / 2, bytes.len() - 1] {
        let mut flipped = bytes.to_vec();
        flipped[position] ^= 1;
        assert!(
            zk().verify(&claim, &PredicateProof::from_bytes(flipped))
                .is_err(),
            "byte {position}"
        );
    }
    let (wide, _) = commit(IntType::U64, 20u64);
    assert!(
        zk().verify(&Predicate::at_least(wide, 18), &proof).is_err(),
        "other circuit and key"
    );
    let (i32c, _) = commit(IntType::I32, 20i32);
    assert!(
        zk().verify(&Predicate::at_least(i32c, 18), &proof).is_err(),
        "other signedness"
    );
}

#[test]
fn claims_travel_as_json() {
    let (c, o) = commit(IntType::I128, -7i32);
    let claim = Predicate::in_range_with(c, -10, 0, true, false);
    let received = Predicate::from_json(&claim.to_json()).unwrap();
    let proof = holds(&claim, &o);
    zk().verify(&received, &proof).unwrap();
}

#[test]
fn an_independent_verifier_accepts_a_proof_from_another_instance() {
    let (c, o) = commit(IntType::U64, 77u64);
    let claim = Predicate::at_least(c, 18);
    let proof = holds(&claim, &o);
    let fresh_verifier = Predicates::new();
    fresh_verifier.verify(&claim, &proof).unwrap();
}
