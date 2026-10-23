//! Real full-ZK proofs for interval unions, claim negation and conjunctions with shared
//! commitments. Nothing is mocked; each success is a Spartan-WHIR proof verified by an independent
//! `Predicates` instance against statements derived from the claims alone.

use std::sync::OnceLock;

use zk_sdk::predicate::{
    self, Commitment, Conjunction, ConjunctionWitness, IntType, Op, Opening, Predicate,
    PredicateProof, Predicates,
};

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(Predicates::new)
}

fn commit(ty: IntType, value: i64) -> (Commitment, Opening) {
    Commitment::commit(ty, value).unwrap()
}

fn prove_one(claim: &Predicate, opening: Opening) -> PredicateProof {
    let proof = zk()
        .prove(claim, opening)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    Predicates::new().verify(claim, &proof).unwrap();
    proof
}

fn unprovable(claim: &Predicate, opening: Opening) {
    assert!(zk().prove(claim, opening).is_err(), "{claim:?}");
}

#[test]
fn an_interval_union_accepts_any_member_interval_and_nothing_else() {
    let ty = IntType::I32;
    let ranges = [(-50, -40), (0, 0), (100, 200)];
    for inside in [-50i64, -45, 0, 100, 150, 200] {
        let (c, o) = commit(ty, inside);
        prove_one(&Predicate::in_any_range(c, ranges), o);
    }
    for outside in [-51i64, -39, -1, 1, 99, 201] {
        let (c, o) = commit(ty, outside);
        unprovable(&Predicate::in_any_range(c, ranges), o);
    }
}

#[test]
fn unused_slots_never_match() {
    // The three disabled slots carry zero bounds; the value 0 must still be refused.
    let (c, o) = commit(IntType::U32, 0);
    unprovable(&Predicate::in_any_range(c, [(5u8, 9u8)]), o);
    let (c, o) = commit(IntType::U64, 7);
    prove_one(&Predicate::in_any_range(c, [(5u8, 9u8)]), o);
}

#[test]
fn a_union_proof_is_bound_to_its_intervals() {
    let (c, o) = commit(IntType::U32, 7);
    let claim = Predicate::in_any_range(c, [(5u8, 9u8), (20, 30)]);
    let proof = prove_one(&claim, o);
    let verifier = Predicates::new();
    for other in [
        Predicate::in_any_range(c, [(5u8, 9u8), (20, 31)]),
        Predicate::in_any_range(c, [(20u8, 30u8), (5, 9)]),
        Predicate::in_any_range(c, [(5u8, 9u8)]),
    ] {
        assert!(verifier.verify(&other, &proof).is_err(), "{other:?}");
    }
}

#[test]
fn negation_flips_exactly_the_claims_that_have_a_flip() {
    let (c, o) = commit(IntType::U32, 20);
    let adult = Predicate::at_least(c, 18);
    let minor = adult.not().unwrap();
    assert_eq!(minor, Predicate::less_than(c, 18));
    assert_eq!(minor.not().unwrap(), adult);
    prove_one(&adult, o.clone());
    unprovable(&minor, o);
    assert!(Predicate::opens(c).not().is_err());
    assert!(Predicate::in_range(c, 1, 2).not().is_err());
}

#[test]
fn a_conjunction_shares_one_opening_across_claims() {
    let (age, age_opening) = commit(IntType::U32, 30);
    let (limit, limit_opening) = commit(IntType::U32, 65);
    let all = Conjunction::new(vec![
        Predicate::at_least(age, 18),
        Predicate::compare_committed(age, Op::Lt, limit),
        Predicate::in_any_range(age, [(18u8, 25u8), (26, 40)]),
    ])
    .unwrap();
    assert_eq!(all.commitments(), vec![age, limit]);
    let witness = || ConjunctionWitness {
        openings: vec![age_opening.clone(), limit_opening.clone()],
        paths: Vec::new(),
    };
    let proof = zk().prove_all(&all, witness()).unwrap();
    let verifier = Predicates::new();
    verifier.verify_all(&all, &proof).unwrap();

    let stronger = Conjunction::new(vec![
        Predicate::at_least(age, 19),
        Predicate::compare_committed(age, Op::Lt, limit),
        Predicate::in_any_range(age, [(18u8, 25u8), (26, 40)]),
    ])
    .unwrap();
    assert!(verifier.verify_all(&stronger, &proof).is_err());
    let shorter = Conjunction::new(all.claims()[..2].to_vec()).unwrap();
    assert!(verifier.verify_all(&shorter, &proof).is_err());
    let reordered = Conjunction::new(vec![
        all.claims()[1].clone(),
        all.claims()[0].clone(),
        all.claims()[2].clone(),
    ])
    .unwrap();
    assert!(verifier.verify_all(&reordered, &proof).is_err());
    let mut damaged = proof.as_bytes().to_vec();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0x55;
    assert!(verifier
        .verify_all(&all, &PredicateProof::from_bytes(damaged))
        .is_err());
    assert!(verifier
        .verify_all(
            &all,
            &PredicateProof::from_bytes(proof.as_bytes()[..40].to_vec())
        )
        .is_err());
}

#[test]
fn one_false_claim_prevents_every_proof() {
    let (age, age_opening) = commit(IntType::U32, 30);
    let all = Conjunction::new(vec![
        Predicate::at_least(age, 18),
        Predicate::at_least(age, 31),
    ])
    .unwrap();
    let error = zk()
        .prove_all(
            &all,
            ConjunctionWitness {
                openings: vec![age_opening],
                paths: Vec::new(),
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("claim 1"), "{error}");
}

#[test]
fn wrong_openings_and_counts_are_refused() {
    let (age, age_opening) = commit(IntType::U32, 30);
    let (other, other_opening) = commit(IntType::U32, 31);
    let all = Conjunction::new(vec![Predicate::at_least(age, 18)]).unwrap();
    for openings in [vec![other_opening], vec![age_opening.clone(), age_opening]] {
        let witness = ConjunctionWitness {
            openings,
            paths: Vec::new(),
        };
        assert!(zk().prove_all(&all, witness).is_err());
    }
    assert_ne!(age, other);
}

#[test]
fn json_entry_points_prove_and_verify_a_conjunction() {
    let a = predicate::commit("u32", "30").unwrap();
    let claim = format!(
        r#"{{"kind":"all","claims":[{{"kind":"compare","commitment":"{c}","op":"ge","bound":"18"}},{{"kind":"compare","commitment":"{c}","op":"le","bound":"65"}}]}}"#,
        c = a.commitment
    );
    let described = predicate::describe(zk(), &claim).unwrap();
    assert_eq!(described.lines().count(), 2);
    let proof = predicate::prove(zk(), &claim, vec![a.secret.clone()]).unwrap();
    predicate::verify(&Predicates::new(), &claim, &proof).unwrap();
    assert!(predicate::prove(zk(), &claim, Vec::new()).is_err());
    assert!(predicate::prove(zk(), &claim, vec![a.secret.clone(), a.secret.clone()]).is_err());
}

#[test]
fn every_interval_union_circuit_attains_the_strict_level() {
    for circuit in ["anyrange_32", "anyrange_64", "anyrange_128"] {
        assert_eq!(zk().security_bits(circuit).unwrap(), 116, "{circuit}");
    }
}
