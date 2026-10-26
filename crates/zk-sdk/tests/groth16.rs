//! Groth16 predicates through the same facade: commitments made for Groth16 are proved over BN254
//! under an ephemeral trusted setup created here from the published phase 1 (no key is stored in
//! the repository) and verified against the claim the verifier trusts. Nothing here is mocked;
//! every success is a real Groth16 proof.

use std::sync::OnceLock;

use zk_sdk::predicate::{
    self, Ceremony, Commitment, Conjunction, ConjunctionWitness, Contribution, CredentialEntry,
    CredentialIssuer, Groth16Setup, IntType, KeyPack, Number, Op, Opening, Predicate,
    PredicateProof, Predicates, Scheme, SetTree, Trust, Witness,
};

fn ceremony() -> &'static Ceremony {
    static CEREMONY: OnceLock<Ceremony> = OnceLock::new();
    CEREMONY.get_or_init(|| predicate::load_ceremony(None, None).unwrap())
}

/// A new setup for `names` with one fresh contribution.
fn create(names: &[String]) -> KeyPack {
    let contribution = Contribution::Random {
        name: Some("sdk test".into()),
    };
    ceremony()
        .create(names, &contribution, &mut |_, _, _| {})
        .unwrap()
}

/// `pack` with the verifier's `trust` list.
fn engine(pack: KeyPack, trust: Trust) -> Predicates {
    Predicates::new().with_groth16(Groth16Setup::new(ceremony().clone(), pack, trust).unwrap())
}

fn trusting(pack: &KeyPack) -> Trust {
    let mut trust = Trust::default();
    trust.insert(pack.setup_id().unwrap());
    trust
}

/// Every approved circuit under one setup the verifier authorized.
fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(|| {
        let pack = create(&predicate::groth16_circuits());
        let trust = trusting(&pack);
        engine(pack, trust)
    })
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
fn wrong_openings_and_mixed_schemes_are_refused() {
    let (c, o) = commit(IntType::U32, 5u8);
    let (_, other) = commit(IntType::U32, 5u8);
    assert!(
        zk().prove(&Predicate::opens(c), other).is_err(),
        "other blinding"
    );
    let (spartan, spartan_o) = Commitment::commit(IntType::U32, 5u8).unwrap();
    assert!(zk().prove(&Predicate::opens(c), spartan_o.clone()).is_err());
    let mixed = Predicate::compare_committed(c, Op::Eq, spartan);
    assert!(zk().prove(&mixed, vec![o, spartan_o]).is_err());
}

#[test]
fn arithmetic_unions_and_distance_prove_over_bn254() {
    for ty in [IntType::I32, IntType::U64, IntType::I128] {
        let (a, oa) = commit(ty, 6u8);
        let (b, ob) = commit(ty, 7u8);
        let (product, op) = commit(ty, 42u8);
        let (total, ot) = commit(ty, 13u8);
        holds(
            &Predicate::multiply(a, b, product),
            vec![oa.clone(), ob.clone(), op.clone()],
        );
        holds(&Predicate::add(a, b, total), vec![oa.clone(), ob, ot]);
        let five = vec![a; 5];
        holds(
            &Predicate::total_compare(five, Op::Eq, 30u8),
            vec![oa.clone(); 5],
        );
        let (quotient, oq) = commit(ty, 2u8);
        holds(
            &Predicate::divide(product, 20u8, quotient, 2u8),
            vec![op, oq],
        );
        holds(
            &Predicate::in_any_range(a, vec![(0, 1), (5, 9)]),
            vec![oa.clone()],
        );
        assert!(zk()
            .prove(&Predicate::in_any_range(a, vec![(0, 1)]), oa)
            .is_err());
    }
    let (x, ox) = commit(IntType::I32, 3);
    let (y, oy) = commit(IntType::I32, -4);
    holds(
        &Predicate::within_distance(x, y, (0, 0), 5u8),
        vec![ox.clone(), oy.clone()],
    );
    assert!(zk()
        .prove(&Predicate::beyond_distance(x, y, (0, 0), 5u8), vec![ox, oy])
        .is_err());
}

#[test]
fn sets_and_credentials_prove_with_groth16_trees() {
    for size in [3u64, 300] {
        let values = (0..size).map(|v| Number::from(v * 2));
        let tree = SetTree::new_in(Scheme::Groth16, IntType::U64, values).unwrap();
        let set = tree.commitment();
        let (even, oe) = commit(IntType::U64, 4u8);
        let (odd, oo) = commit(IntType::U64, 5u8);
        let member = Predicate::member_of(even, set);
        let proof = zk()
            .prove(
                &member,
                Witness::from(oe).with_path(tree.member_path(4u8).unwrap()),
            )
            .unwrap();
        zk().verify(&member, &proof).unwrap();
        let absent = Predicate::not_member_of(odd, set);
        let witness = Witness::from(oo).with_path(tree.absence_path(5u8).unwrap());
        let proof = zk().prove(&absent, witness).unwrap();
        zk().verify(&absent, &proof).unwrap();
        let spartan = SetTree::new(IntType::U64, [Number::from(4u8)]).unwrap();
        assert!(Predicate::member_of(even, spartan.commitment())
            .statement()
            .is_err());
    }
    let entry = CredentialEntry {
        attribute: Number::from(30u8),
        serial: 11,
        expiry: 5_000,
    };
    let issuer = CredentialIssuer::new_in(Scheme::Groth16, IntType::U32, [entry]).unwrap();
    let presentation = issuer.credential(11).unwrap().present(100).unwrap();
    let revoked = SetTree::new_in(Scheme::Groth16, IntType::U64, [Number::from(12u8)]).unwrap();
    let adult = Predicate::at_least(presentation.attribute(), 18);
    let (claim, witness) = presentation.all(vec![adult], Some(&revoked)).unwrap();
    let proof = zk().prove_all(&claim, witness).unwrap();
    zk().verify_all(&claim, &proof).unwrap();
}

#[test]
fn proofs_verify_only_under_the_setup_the_verifier_authorized() {
    let (c, o) = commit(IntType::U32, 20u8);
    let claim = Predicate::at_least(c, 18);
    let proof = zk().prove(&claim, o.clone()).unwrap();
    let other = create(&[claim.statement().unwrap().circuit().to_owned()]);
    let other_trust = trusting(&other);
    let theirs = engine(other.clone(), other_trust.clone());
    let their_proof = theirs.prove(&claim, o.clone()).unwrap();
    theirs.verify(&claim, &their_proof).unwrap();
    assert!(
        theirs.verify(&claim, &proof).is_err(),
        "another setup's proof"
    );
    assert!(zk().verify(&claim, &their_proof).is_err(), "and back");

    let unauthorized = engine(other.clone(), Trust::default());
    assert!(
        unauthorized.prove(&claim, o).is_ok(),
        "proving needs no trust"
    );
    assert!(unauthorized.verify(&claim, &their_proof).is_err());
    let missing = engine(other, other_trust);
    let (wide, wide_o) = commit(IntType::U128, 20u8);
    assert!(
        missing
            .prove(&Predicate::at_least(wide, 18), wide_o)
            .is_err(),
        "a circuit outside the setup"
    );
    let none = Predicates::new();
    assert!(none.verify(&claim, &proof).is_err(), "no setup at all");
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
