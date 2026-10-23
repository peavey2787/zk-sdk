//! Real full-ZK proofs for the arithmetic and conservation predicates: sums, conservation with
//! fees and supply changes, products, bounded division, mixed public/private operands, all six
//! integer types, and tampering. Nothing is mocked; each success is a Spartan-WHIR proof verified
//! by an independent `Predicates` instance against a statement derived from the claim alone.

use std::sync::OnceLock;

use zk_sdk::predicate::{Commitment, IntType, Number, Op, Opening, Predicate, Predicates};

/// The larger circuits attain 115 bits at most; this opt-in is the only way to run them.
fn authorized() -> Predicates {
    Predicates::new().with_minimum_bits(115)
}

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(authorized)
}

fn commit(ty: IntType, value: impl Into<Number>) -> (Commitment, Opening) {
    Commitment::commit(ty, value).unwrap()
}

/// Prove with `openings` (in claim order) and verify with a fresh, independent verifier.
fn holds(claim: &Predicate, openings: Vec<Opening>) -> zk_sdk::predicate::PredicateProof {
    let proof = zk()
        .prove(claim, openings)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    authorized()
        .verify(claim, &proof)
        .unwrap_or_else(|e| panic!("{claim:?}: {e}"));
    proof
}

fn is_false(claim: &Predicate, openings: Vec<Opening>) {
    assert!(
        zk().prove(claim, openings).is_err(),
        "a false claim must not be provable: {claim:?}"
    );
}

#[test]
fn conservation_with_fees_across_every_type() {
    for ty in [
        IntType::U32,
        IntType::I32,
        IntType::U64,
        IntType::I64,
        IntType::U128,
        IntType::I128,
    ] {
        let (a, oa) = commit(ty, 700u32);
        let (b, ob) = commit(ty, 300u32);
        let (c, oc) = commit(ty, 960u32);
        let (d, od) = commit(ty, 30u32);
        let claim = Predicate::conserve(vec![a, b], vec![c, d], 10u8);
        let proof = holds(&claim, vec![oa, ob, oc, od]);
        let verifier = authorized();
        assert!(verifier
            .verify(&Predicate::conserve(vec![a, b], vec![c, d], 11u8), &proof)
            .is_err());
        assert!(verifier
            .verify(&Predicate::conserve(vec![a, b], vec![d, c], 10u8), &proof)
            .is_err());
    }
}

#[test]
fn unbalanced_conservation_has_no_proof() {
    let (a, oa) = commit(IntType::U64, 100u8);
    let (b, ob) = commit(IntType::U64, 99u8);
    is_false(
        &Predicate::conserve(vec![a], vec![b], 0u8),
        vec![oa.clone(), ob.clone()],
    );
    is_false(
        &Predicate::conserve(vec![a], vec![b], 2u8),
        vec![oa.clone(), ob.clone()],
    );
    holds(&Predicate::conserve(vec![a], vec![b], 1u8), vec![oa, ob]);
}

#[test]
fn conservation_does_not_wrap_at_the_type_width() {
    // Two u32 maxima sum to 2^33 - 2, which a wrapping check would confuse with 2^32 - 2.
    let (a, oa) = commit(IntType::U32, u32::MAX);
    let (b, ob) = commit(IntType::U32, u32::MAX);
    let (wrapped, ow) = commit(IntType::U32, u32::MAX - 1);
    is_false(
        &Predicate::sum_equals(vec![a, b], wrapped),
        vec![oa.clone(), ob.clone(), ow],
    );
    let (half, oh) = commit(IntType::U32, u32::MAX);
    holds(
        &Predicate::sum(vec![a, b], 0u8, Op::Eq, vec![half], u32::MAX),
        vec![oa.clone(), ob.clone(), oh.clone()],
    );
    is_false(
        &Predicate::sum(vec![a, b], 0u8, Op::Eq, vec![half], 1u8),
        vec![oa, ob, oh],
    );
}

#[test]
fn signed_sums_cross_zero() {
    let (a, oa) = commit(IntType::I64, -50i64);
    let (b, ob) = commit(IntType::I64, 20i64);
    let (total, ot) = commit(IntType::I64, -30i64);
    holds(
        &Predicate::add(a, b, total),
        vec![oa.clone(), ob.clone(), ot.clone()],
    );
    holds(
        &Predicate::subtract(total, a, b),
        vec![ot.clone(), oa.clone(), ob.clone()],
    );
    is_false(&Predicate::add(a, b, a), vec![oa.clone(), ob.clone(), oa]);
    is_false(&Predicate::add(a, b, total), vec![ob.clone(), ob, ot]);
}

#[test]
fn mint_and_burn_are_explicit_and_authorised() {
    let (i, oi) = commit(IntType::U64, 1000u32);
    let (o, oo) = commit(IntType::U64, 1250u32);
    let claim = Predicate::conserve_with_supply(vec![i], vec![o], 5u8, 300u32, 45u8).unwrap();
    holds(&claim, vec![oi.clone(), oo.clone()]);
    let unauthorised =
        Predicate::conserve_with_supply(vec![i], vec![o], 5u8, 299u32, 45u8).unwrap();
    is_false(&unauthorised, vec![oi, oo]);
}

#[test]
fn balance_invariants_over_bounded_collections() {
    let values = [5u32, 7, 9, 11, 13, 15, 17, 19];
    let (commitments, openings): (Vec<_>, Vec<_>) =
        values.iter().map(|v| commit(IntType::U32, *v)).unzip();
    let total: u32 = values.iter().sum();
    holds(
        &Predicate::total_compare(commitments.clone(), Op::Eq, total),
        openings.clone(),
    );
    holds(
        &Predicate::total_compare(commitments.clone(), Op::Ge, total - 1),
        openings.clone(),
    );
    holds(
        &Predicate::total_compare(commitments.clone(), Op::Le, total + 100),
        openings.clone(),
    );
    is_false(
        &Predicate::total_compare(commitments.clone(), Op::Gt, total),
        openings.clone(),
    );
    let mut too_many = commitments.clone();
    too_many.push(commitments[0]);
    let mut too_many_openings = openings;
    too_many_openings.push(too_many_openings[0].clone());
    assert!(zk()
        .prove(
            &Predicate::total_compare(too_many, Op::Ge, 0u8),
            too_many_openings
        )
        .is_err());
}

#[test]
fn products_exact_and_overflow_free() {
    let (x, ox) = commit(IntType::I64, -6i64);
    let (y, oy) = commit(IntType::I64, 7i64);
    let (p, op) = commit(IntType::I64, -42i64);
    holds(
        &Predicate::multiply(x, y, p),
        vec![ox.clone(), oy.clone(), op.clone()],
    );
    let (wrong, ow) = commit(IntType::I64, 42i64);
    is_false(&Predicate::multiply(x, y, wrong), vec![ox, oy, ow]);

    // 2^40 * 2^40 does not fit u64: the exact product is not the wrapped zero.
    let (big, ob) = commit(IntType::U64, 1u64 << 40);
    let (zero, oz) = commit(IntType::U64, 0u8);
    is_false(
        &Predicate::multiply(big, big, zero),
        vec![ob.clone(), ob.clone(), oz],
    );
    // x * y + z compared against a public bound.
    holds(
        &Predicate::arithmetic(big, 3u8, 5u8, Op::Gt, 1000u32),
        vec![ob],
    );
}

#[test]
fn mixed_public_and_private_operands() {
    let (price, oprice) = commit(IntType::U64, 25u8);
    let (total, ototal) = commit(IntType::U64, 125u8);
    holds(
        &Predicate::multiply(price, 5u8, total),
        vec![oprice.clone(), ototal.clone()],
    );
    is_false(
        &Predicate::multiply(price, 6u8, total),
        vec![oprice, ototal],
    );
    assert!(
        zk().prove(&Predicate::multiply(3u8, 4u8, 12u8), Vec::<Opening>::new())
            .is_err(),
        "at least one operand must be committed"
    );
}

#[test]
fn bounded_division_with_explicit_remainder() {
    for ty in [IntType::U32, IntType::I64, IntType::U128] {
        let (dividend, od) = commit(ty, 47u8);
        let (quotient, oq) = commit(ty, 5u8);
        let (remainder, orm) = commit(ty, 2u8);
        let claim = Predicate::divide(dividend, 9u8, quotient, remainder);
        holds(&claim, vec![od.clone(), oq.clone(), orm.clone()]);
        let (bad_remainder, obr) = commit(ty, 11u8);
        let (bad_quotient, obq) = commit(ty, 4u8);
        let overlarge = Predicate::divide(dividend, 9u8, bad_quotient, bad_remainder);
        is_false(&overlarge, vec![od.clone(), obq, obr]);
        let zero_divisor = Predicate::divide(dividend, 0u8, quotient, remainder);
        is_false(&zero_divisor, vec![od, oq, orm]);
    }
}

#[test]
fn tampered_claims_and_proofs_are_rejected() {
    let (a, oa) = commit(IntType::U64, 8u8);
    let (b, ob) = commit(IntType::U64, 5u8);
    let (c, oc) = commit(IntType::U64, 3u8);
    let claim = Predicate::subtract(a, b, c);
    let proof = holds(&claim, vec![oa.clone(), ob.clone(), oc.clone()]);
    let verifier = authorized();
    assert!(verifier
        .verify(&Predicate::subtract(a, c, b), &proof)
        .is_err());
    assert!(verifier.verify(&Predicate::add(a, b, c), &proof).is_err());
    let (other, _) = commit(IntType::U64, 3u8);
    assert!(
        verifier
            .verify(&Predicate::subtract(a, b, other), &proof)
            .is_err(),
        "other blinding"
    );

    let mut bytes = proof.as_bytes().to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    let corrupted = zk_sdk::predicate::PredicateProof::from_bytes(bytes);
    assert!(verifier.verify(&claim, &corrupted).is_err());
    let truncated = zk_sdk::predicate::PredicateProof::from_bytes(proof.as_bytes()[..64].to_vec());
    assert!(verifier.verify(&claim, &truncated).is_err());

    let (mixed, om) = commit(IntType::I64, 3u8);
    assert!(
        zk().prove(&Predicate::subtract(a, b, mixed), vec![oa, ob, om])
            .is_err(),
        "mixed types"
    );
}

#[test]
fn a_witness_from_the_wrong_commitment_is_refused() {
    let (a, oa) = commit(IntType::U64, 8u8);
    let (b, _) = commit(IntType::U64, 5u8);
    let (_, other) = commit(IntType::U64, 5u8);
    let (c, oc) = commit(IntType::U64, 3u8);
    assert!(zk()
        .prove(&Predicate::subtract(a, b, c), vec![oa, other, oc])
        .is_err());
}

#[test]
fn claims_round_trip_through_json() {
    let (a, _) = commit(IntType::U64, 8u8);
    let (b, _) = commit(IntType::U64, 5u8);
    for claim in [
        Predicate::conserve(vec![a, b], vec![a], 4u8),
        Predicate::multiply(a, 7u8, b),
        Predicate::divide(a, 3u8, b, 2u8),
    ] {
        assert_eq!(Predicate::from_json(&claim.to_json()).unwrap(), claim);
    }
}

#[test]
fn attained_security_is_reported_and_never_below_the_backend_floor() {
    for circuit in ["compare_32", "sum4_32", "sum4_64", "sum8_128", "arith_128"] {
        let bits = zk().security_bits(circuit).unwrap();
        assert!((100..=116).contains(&bits), "{circuit}: {bits}");
        println!("{circuit}: {bits} bits");
    }
}

#[test]
fn false_claims_say_why() {
    let (a, oa) = commit(IntType::U64, 100u8);
    let (b, ob) = commit(IntType::U64, 99u8);
    let reason = |claim: &Predicate, openings: Vec<Opening>| {
        zk().prove(claim, openings).err().unwrap().to_string()
    };
    let message = reason(
        &Predicate::conserve(vec![a], vec![b], 0u8),
        vec![oa.clone(), ob.clone()],
    );
    assert!(
        message.contains("plus side is greater than the minus side"),
        "{message}"
    );
    let message = reason(&Predicate::at_most(a, 5u8), vec![oa.clone()]);
    assert!(
        message.contains("committed value is greater than the bound"),
        "{message}"
    );
    let message = reason(&Predicate::divide(a, 0u8, b, 0u8), vec![oa, ob]);
    assert!(message.contains("divisor must be positive"), "{message}");
}

#[test]
fn lower_security_needs_explicit_authorization() {
    let (a, oa) = commit(IntType::U64, 5u8);
    let (b, ob) = commit(IntType::U64, 4u8);
    let claim = Predicate::conserve(vec![a], vec![b], 1u8);
    let strict = Predicates::new();
    assert!(matches!(
        strict.prove(&claim, vec![oa.clone(), ob.clone()]),
        Err(zk_sdk::ZkError::SecurityUnattainable {
            requested: 116,
            attainable: 115
        })
    ));
    let too_high = Predicates::new().with_minimum_bits(116);
    assert!(too_high
        .prove(&claim, vec![oa.clone(), ob.clone()])
        .is_err());
    let proof = holds(&claim, vec![oa, ob]);
    assert!(strict.verify(&claim, &proof).is_err());
}
