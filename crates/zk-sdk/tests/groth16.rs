//! Groth16 predicates through the same facade: commitments made for Groth16 are proved over BN254
//! with the bundled phase-2 keys and verified against the claim the verifier trusts. Nothing here
//! is mocked; every success is a real Groth16 proof.

use std::sync::OnceLock;

use zk_sdk::predicate::{
    Commitment, Conjunction, ConjunctionWitness, IntType, Number, Op, Opening, Predicate,
    PredicateProof, Predicates, Scheme,
};

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(Predicates::new)
}

fn commit(ty: IntType, value: impl Into<Number>) -> (Commitment, Opening) {
    Commitment::commit_in(Scheme::Groth16, ty, value).unwrap()
}

fn holds(claim: &Predicate, witness: Vec<Opening>) -> PredicateProof {
    let proof = zk()
        .prove(claim, witness)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    zk().verify(claim, &proof)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    proof
}

const TYPES: [IntType; 6] = [
    IntType::U32,
    IntType::I32,
    IntType::U64,
    IntType::I64,
    IntType::U128,
    IntType::I128,
];

#[test]
fn every_family_proves_at_every_type_and_binds_its_statement() {
    for ty in TYPES {
        let (c, o) = commit(ty, 7u8);
        let (big, big_o) = commit(ty, 9u8);
        let proof = holds(&Predicate::opens(c), vec![o.clone()]);
        assert!(zk().verify(&Predicate::opens(big), &proof).is_err(), "{ty}");

        let proof = holds(&Predicate::at_least(c, 7), vec![o.clone()]);
        assert!(
            zk().verify(&Predicate::at_least(c, 8), &proof).is_err(),
            "{ty}"
        );
        assert!(
            zk().prove(&Predicate::at_least(c, 8), o.clone()).is_err(),
            "{ty}"
        );

        let range = Predicate::in_range_with(c, 7, 9, true, false);
        let proof = holds(&range, vec![o.clone()]);
        let other = Predicate::in_range_with(c, 7, 9, true, true);
        assert!(zk().verify(&other, &proof).is_err(), "{ty}");
        let exclusive = Predicate::in_range_with(c, 7, 9, false, false);
        assert!(zk().prove(&exclusive, o.clone()).is_err(), "{ty}");

        let pair = Predicate::compare_committed(c, Op::Lt, big);
        let proof = holds(&pair, vec![o.clone(), big_o.clone()]);
        let swapped = Predicate::compare_committed(big, Op::Lt, c);
        assert!(zk().verify(&swapped, &proof).is_err(), "{ty}");
        assert!(zk().prove(&swapped, vec![big_o, o]).is_err(), "{ty}");
    }
}

#[test]
fn signed_extremes_compare_correctly() {
    let (c, o) = commit(IntType::I128, i128::MIN);
    holds(&Predicate::less_than(c, i128::MAX), vec![o.clone()]);
    holds(&Predicate::equals(c, i128::MIN), vec![o.clone()]);
    assert!(zk().prove(&Predicate::greater_than(c, -1), o).is_err());
}

#[test]
fn proofs_are_compact_and_reject_tampering_and_other_schemes() {
    let (c, o) = commit(IntType::U64, 20u8);
    let claim = Predicate::at_least(c, 18);
    let proof = holds(&claim, vec![o]);
    assert_eq!(
        proof.as_bytes().len(),
        8 + 128,
        "tag plus a compressed Groth16 proof"
    );
    for index in [0, 8, 40, proof.as_bytes().len() - 1] {
        let mut bytes = proof.as_bytes().to_vec();
        bytes[index] ^= 1;
        let tampered = PredicateProof::from_bytes(bytes);
        assert!(zk().verify(&claim, &tampered).is_err(), "byte {index}");
    }
    let truncated = PredicateProof::from_bytes(proof.as_bytes()[..100].to_vec());
    assert!(zk().verify(&claim, &truncated).is_err());

    let (spartan, spartan_o) = Commitment::commit(IntType::U64, 20u8).unwrap();
    let spartan_claim = Predicate::at_least(spartan, 18);
    let spartan_proof = zk().prove(&spartan_claim, spartan_o).unwrap();
    assert!(zk().verify(&claim, &spartan_proof).is_err());
    assert!(zk().verify(&spartan_claim, &proof).is_err());
}

#[test]
fn wrong_openings_mixed_schemes_and_missing_circuits_are_refused() {
    let (c, o) = commit(IntType::U32, 5u8);
    let (_, other) = commit(IntType::U32, 5u8);
    assert!(
        zk().prove(&Predicate::opens(c), other).is_err(),
        "other blinding"
    );
    let (spartan, spartan_o) = Commitment::commit(IntType::U32, 5u8).unwrap();
    assert!(zk().prove(&Predicate::opens(c), spartan_o.clone()).is_err());
    let mixed = Predicate::compare_committed(c, Op::Eq, spartan);
    assert!(zk().prove(&mixed, vec![o.clone(), spartan_o]).is_err());
    assert!(Predicate::multiply(c, 2, c).statement().is_err());
    assert!(Predicate::in_any_range(c, vec![(1, 2)])
        .statement()
        .is_err());
    assert!(zk()
        .prove(&Predicate::multiply(c, 2, c), vec![o.clone(), o])
        .is_err());
}

#[test]
fn conjunctions_share_one_opening_per_commitment() {
    let (age, age_o) = commit(IntType::U32, 30u8);
    let (cap, cap_o) = commit(IntType::U32, 40u8);
    let claim = Conjunction::new(vec![
        Predicate::in_range(age, 18, 65),
        Predicate::compare_committed(age, Op::Lt, cap),
    ])
    .unwrap();
    let witness = || ConjunctionWitness {
        openings: vec![age_o.clone(), cap_o.clone()],
        paths: vec![],
    };
    let proof = zk().prove_all(&claim, witness()).unwrap();
    zk().verify_all(&claim, &proof).unwrap();
    let other = Conjunction::new(vec![
        Predicate::in_range(age, 18, 64),
        Predicate::compare_committed(age, Op::Lt, cap),
    ])
    .unwrap();
    assert!(zk().verify_all(&other, &proof).is_err());
}
