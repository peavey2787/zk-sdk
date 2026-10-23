//! Real full-ZK proofs for set membership and non-membership against published Merkle roots.
//! Nothing is mocked; each success is a Spartan-WHIR proof verified by an independent
//! `Predicates` instance against a statement derived from the claim alone.

use std::sync::OnceLock;

use zk_sdk::predicate::{
    Commitment, IntType, Number, Opening, Predicate, PredicateProof, Predicates, SetCommitment,
    SetPath, SetTree,
};

/// The Merkle-path circuits exceed the size upstream supports at 116 bits; this opt-in is the only
/// way to run them.
fn authorized() -> Predicates {
    Predicates::new().with_minimum_bits(115)
}

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(authorized)
}

fn tree(ty: IntType, values: &[i64]) -> SetTree {
    SetTree::new(ty, values.iter().map(|v| Number::from(*v))).unwrap()
}

fn commit(ty: IntType, value: i64) -> (Commitment, Opening) {
    Commitment::commit(ty, value).unwrap()
}

fn prove(claim: &Predicate, opening: Opening, path: SetPath) -> PredicateProof {
    let proof = zk()
        .prove(
            claim,
            zk_sdk::predicate::Witness::from(opening).with_path(path),
        )
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    authorized()
        .verify(claim, &proof)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    proof
}

#[test]
fn membership_and_absence_prove_for_signed_values() {
    let ty = IntType::I32;
    let set = tree(ty, &[-40, -1, 0, 7, 1000, 2_000_000]);
    let root = set.commitment();
    for member in [-40i64, 0, 2_000_000] {
        let (c, o) = commit(ty, member);
        let claim = Predicate::member_of(c, root);
        prove(&claim, o, set.member_path(member).unwrap());
    }
    for stranger in [
        -100i64,
        -2,
        1,
        999,
        i64::from(i32::MAX),
        i64::from(i32::MIN),
    ] {
        let (c, o) = commit(ty, stranger);
        let claim = Predicate::not_member_of(c, root);
        prove(&claim, o, set.absence_path(stranger).unwrap());
    }
}

#[test]
fn the_empty_set_proves_absence_of_anything() {
    let ty = IntType::U64;
    let set = tree(ty, &[]);
    let (c, o) = commit(ty, 123);
    prove(
        &Predicate::not_member_of(c, set.commitment()),
        o,
        set.absence_path(123u8).unwrap(),
    );
}

#[test]
fn false_claims_cannot_be_proved() {
    let ty = IntType::U32;
    let set = tree(ty, &[10, 20, 30]);
    let other = tree(ty, &[10, 20, 31]);
    let root = set.commitment();

    // A stranger claiming membership, with any path another value owns.
    let (c, o) = commit(ty, 15);
    let member_claim = Predicate::member_of(c, root);
    let borrowed = set.member_path(20u8).unwrap();
    let witness = zk_sdk::predicate::Witness::from(o.clone()).with_path(borrowed);
    assert!(zk().prove(&member_claim, witness).is_err());

    // A member claiming absence.
    let (c, o) = commit(ty, 20);
    let absent_claim = Predicate::not_member_of(c, root);
    let gap = set.absence_path(15u8).unwrap();
    assert!(zk()
        .prove(
            &absent_claim,
            zk_sdk::predicate::Witness::from(o.clone()).with_path(gap)
        )
        .is_err());

    // A path into a different set, and no path at all.
    let wrong_set = other.member_path(31u8).unwrap();
    assert!(zk()
        .prove(
            &Predicate::member_of(c, root),
            zk_sdk::predicate::Witness::from(o.clone()).with_path(wrong_set)
        )
        .is_err());
    assert!(zk().prove(&Predicate::member_of(c, root), o).is_err());
}

#[test]
fn a_proof_is_bound_to_its_set_commitment_and_kind() {
    let ty = IntType::U64;
    let set = tree(ty, &[5, 6, 7]);
    let other = tree(ty, &[5, 6, 8]);
    let (c, o) = commit(ty, 6);
    let claim = Predicate::member_of(c, set.commitment());
    let proof = prove(&claim, o, set.member_path(6u8).unwrap());
    let verifier = authorized();
    assert!(verifier
        .verify(&Predicate::member_of(c, other.commitment()), &proof)
        .is_err());
    assert!(verifier
        .verify(&Predicate::not_member_of(c, set.commitment()), &proof)
        .is_err());
    let (elsewhere, _) = commit(ty, 6);
    assert!(verifier
        .verify(&Predicate::member_of(elsewhere, set.commitment()), &proof)
        .is_err());
}

#[test]
fn a_set_of_another_type_is_refused() {
    let set = tree(IntType::U32, &[1]);
    let (c, _) = commit(IntType::U64, 1);
    assert!(Predicate::member_of(c, set.commitment())
        .statement()
        .is_err());
}

#[test]
fn large_sets_use_the_deep_circuit() {
    let ty = IntType::U32;
    let set = SetTree::new(ty, (0..1000u32).map(|v| Number::from(v * 2))).unwrap();
    assert_eq!(set.commitment().depth(), 20);
    let (c, o) = commit(ty, 1998);
    prove(
        &Predicate::member_of(c, set.commitment()),
        o,
        set.member_path(1998u32).unwrap(),
    );
    let (c, o) = commit(ty, 1999);
    prove(
        &Predicate::not_member_of(c, set.commitment()),
        o,
        set.absence_path(1999u32).unwrap(),
    );
}

#[test]
fn claims_round_trip_through_json() {
    let set = tree(IntType::I64, &[1, 2]);
    let (c, _) = commit(IntType::I64, 1);
    for claim in [
        Predicate::member_of(c, set.commitment()),
        Predicate::not_member_of(c, set.commitment()),
    ] {
        assert_eq!(Predicate::from_json(&claim.to_json()).unwrap(), claim);
    }
    let text = set.commitment().to_text();
    assert_eq!(SetCommitment::from_text(&text).unwrap(), set.commitment());
}
