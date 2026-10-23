//! Real full-ZK proofs for the proximity claim: a committed point against a public centre and
//! radius, compared on exact squared distances. Nothing is mocked; each success is a Spartan-WHIR
//! proof verified by an independent `Predicates` instance against a statement derived from the
//! claim alone.

use std::sync::OnceLock;

use zk_sdk::predicate::{Commitment, IntType, Op, Opening, Predicate, PredicateProof, Predicates};

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(Predicates::new)
}

fn point(ty: IntType, x: i64, y: i64) -> (Commitment, Commitment, Vec<Opening>) {
    let (cx, ox) = Commitment::commit(ty, x).unwrap();
    let (cy, oy) = Commitment::commit(ty, y).unwrap();
    (cx, cy, vec![ox, oy])
}

fn prove(claim: &Predicate, openings: Vec<Opening>) -> PredicateProof {
    let proof = zk()
        .prove(claim, openings)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    Predicates::new()
        .verify(claim, &proof)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    proof
}

#[test]
fn a_point_exactly_on_the_boundary_is_within_distance() {
    let (x, y, openings) = point(IntType::I32, 3, -4);
    prove(&Predicate::within_distance(x, y, (0, 0), 5u8), openings);
}

#[test]
fn the_centre_need_not_be_the_origin_and_may_be_negative() {
    let (x, y, openings) = point(IntType::I64, -1_000_003, 2_000_004);
    let claim = Predicate::within_distance(x, y, (-1_000_000, 2_000_000), 5u8);
    prove(&claim, openings);
}

#[test]
fn a_point_just_outside_is_not_provable_as_within() {
    let (x, y, openings) = point(IntType::I32, 3, -4);
    let claim = Predicate::within_distance(x, y, (0, 0), 4u8);
    let error = zk().prove(&claim, openings).unwrap_err().to_string();
    assert!(error.contains("squared distance"), "{error}");
}

#[test]
fn beyond_and_exact_distance_use_the_same_circuit() {
    let (x, y, openings) = point(IntType::I32, 3, -4);
    prove(
        &Predicate::beyond_distance(x, y, (0, 0), 4u8),
        openings.clone(),
    );
    prove(&Predicate::distance(x, y, (0, 0), Op::Eq, 5u8), openings);
}

#[test]
fn unsigned_types_and_the_widest_coordinates_do_not_wrap() {
    let ty = IntType::U32;
    let far = i64::from(u32::MAX);
    let (x, y, openings) = point(ty, far, 0);
    // The distance from (2^32 - 1, 0) to the origin is exactly 2^32 - 1, whose square needs 64 bits.
    prove(
        &Predicate::within_distance(x, y, (0u8, 0u8), u32::MAX),
        openings.clone(),
    );
    assert!(zk()
        .prove(
            &Predicate::within_distance(x, y, (0u8, 0u8), u32::MAX - 1),
            openings,
        )
        .is_err());
}

#[test]
fn a_proof_is_bound_to_the_centre_radius_and_commitments() {
    let (x, y, openings) = point(IntType::I32, 3, -4);
    let claim = Predicate::within_distance(x, y, (0, 0), 5u8);
    let proof = prove(&claim, openings);
    let verifier = Predicates::new();
    for other in [
        Predicate::within_distance(x, y, (0, 0), 6u8),
        Predicate::within_distance(x, y, (1, 0), 5u8),
        Predicate::within_distance(x, y, (0, 1), 5u8),
        Predicate::within_distance(y, x, (0, 0), 5u8),
        Predicate::beyond_distance(x, y, (0, 0), 5u8),
    ] {
        assert!(verifier.verify(&other, &proof).is_err(), "{other:?}");
    }
}

#[test]
fn openings_for_other_commitments_cannot_prove_the_claim() {
    let (x, y, _) = point(IntType::I32, 3, -4);
    let (_, _, wrong) = point(IntType::I32, 0, 0);
    let claim = Predicate::within_distance(x, y, (0, 0), 5u8);
    assert!(zk().prove(&claim, wrong).is_err());
}

#[test]
fn only_the_128_bit_circuit_needs_the_115_bit_opt_in() {
    assert_eq!(zk().security_bits("distance_32").unwrap(), 116);
    assert_eq!(zk().security_bits("distance_64").unwrap(), 116);
    assert!(zk().security_bits("distance_128").is_err());
    let relaxed = Predicates::new().with_minimum_bits(115);
    assert_eq!(relaxed.security_bits("distance_128").unwrap(), 115);
}
