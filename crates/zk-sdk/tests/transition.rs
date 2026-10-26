//! Real full-ZK proofs for private state transitions: a ledger-style balance step, a guard that
//! fails, tampered rules, and a two-step chain linked by commitment identity.

use std::sync::OnceLock;

use zk_sdk::predicate::{Commitment, IntType, Number, Op, Opening, Predicates, Rule, Transition};

/// The conservation circuits exceed 8192 constraints, which upstream attains only at 115 bits.
fn verifier() -> Predicates {
    Predicates::new().with_minimum_bits(115)
}

fn zk() -> &'static Predicates {
    static ZK: OnceLock<Predicates> = OnceLock::new();
    ZK.get_or_init(verifier)
}

fn state(values: &[u64]) -> (Vec<Commitment>, Vec<Opening>) {
    values
        .iter()
        .map(|&v| Commitment::commit(IntType::U64, v).unwrap())
        .unzip()
}

fn rules() -> Vec<Rule> {
    vec![
        Rule::Require {
            field: 0,
            op: Op::Ge,
            bound: Number::from(50u64),
        },
        Rule::Conserve {
            fields: vec![0, 1],
            fee: Number::from(2u64),
        },
        Rule::Add {
            field: 2,
            delta: Number::from(1u64),
        },
        Rule::Ensure {
            field: 0,
            op: Op::Ge,
            bound: Number::from(0u64),
        },
    ]
}

fn step(old: &[u64], new: &[u64]) -> (Transition, Vec<Opening>) {
    let ((old_c, mut openings), (new_c, new_o)) = (state(old), state(new));
    openings.extend(new_o);
    (Transition::new(old_c, new_c, &rules()).unwrap(), openings)
}

#[test]
fn a_valid_step_proves_and_verifies_against_the_rules_alone() {
    // balances 100 / 10 move to 70 / 38 (fee 2); the counter goes 4 -> 5.
    let (t, mut openings) = step(&[100, 10, 4], &[70, 38, 5]);
    openings.reverse(); // any order is accepted
    let proof = zk()
        .prove_all(t.claim(), t.witness(openings).unwrap())
        .unwrap();
    verifier().verify_all(t.claim(), &proof).unwrap();

    // The same proof does not verify for a different fee or a different delta.
    let mut other = rules();
    other[1] = Rule::Conserve {
        fields: vec![0, 1],
        fee: Number::from(3u64),
    };
    let tampered = Transition::new(t.old().to_vec(), t.new_state().to_vec(), &other).unwrap();
    assert!(Predicates::new()
        .verify_all(tampered.claim(), &proof)
        .is_err());
}

#[test]
fn a_step_breaking_a_rule_has_no_proof() {
    for (old, new) in [
        (&[40u64, 70, 4], &[10u64, 98, 5]), // guard: old balance below 50
        (&[100, 10, 4], &[70, 39, 5]),      // value created
        (&[100, 10, 4], &[70, 38, 6]),      // counter skipped
    ] {
        let (t, openings) = step(old, new);
        assert!(zk()
            .prove_all(t.claim(), t.witness(openings).unwrap())
            .is_err());
    }
}

#[test]
fn steps_chain_by_commitment_identity() {
    let (first_old, first_new) = (state(&[100, 10, 4]), state(&[70, 38, 5]));
    let second_new = state(&[40, 66, 6]);
    let first = Transition::new(first_old.0.clone(), first_new.0.clone(), &rules()).unwrap();
    let second = Transition::new(first_new.0.clone(), second_new.0.clone(), &rules()).unwrap();
    assert!(second.follows(&first) && !first.follows(&second));

    let openings = [first_old.1, first_new.1.clone(), second_new.1]
        .concat()
        .into_iter()
        .collect::<Vec<_>>();
    for t in [&first, &second] {
        let proof = zk()
            .prove_all(t.claim(), t.witness(openings.clone()).unwrap())
            .unwrap();
        verifier().verify_all(t.claim(), &proof).unwrap();
    }
}

#[test]
fn malformed_transitions_are_rejected() {
    let (old, _) = state(&[1, 2]);
    let (short, _) = state(&[1]);
    let (wide, _) = (
        vec![Commitment::commit(IntType::U32, 1u32).unwrap().0; 2],
        (),
    );
    assert!(Transition::new(old.clone(), short, &rules()).is_err());
    assert!(Transition::new(old.clone(), wide, &rules()).is_err());
    let out_of_range = [Rule::Add {
        field: 5,
        delta: Number::from(1u64),
    }];
    assert!(Transition::new(old.clone(), old.clone(), &out_of_range).is_err());
    assert!(Transition::new(old.clone(), old, &[]).is_err());
}

#[test]
fn json_entry_points_lower_and_prove_a_transition() {
    use zk_sdk::predicate;
    let made: Vec<_> = ["100", "10", "70", "38"]
        .iter()
        .map(|v| predicate::commit("spartan-whir", "u64", v).unwrap())
        .collect();
    let text = |i: usize| made[i].commitment.clone();
    let spec = format!(
        r#"{{"old":["{}","{}"],"new":["{}","{}"],"rules":[
            {{"kind":"require","field":0,"op":"ge","bound":"50"}},
            {{"kind":"conserve","fields":[0,1],"fee":"2"}}]}}"#,
        text(0),
        text(1),
        text(2),
        text(3)
    );
    let lowered = predicate::transition_claim(&spec).unwrap();
    // Secrets follow the `open` order, whatever order the commitments were listed in.
    let secrets: Vec<String> = lowered
        .open
        .iter()
        .map(|c| {
            made.iter()
                .find(|m| &m.commitment == c)
                .unwrap()
                .secret
                .clone()
        })
        .collect();
    let proof = predicate::prove(&verifier(), &lowered.claim, secrets).unwrap();
    predicate::verify(&verifier(), &lowered.claim, &proof).unwrap();
    assert!(
        predicate::transition_claim(&spec.replace("\"fee\":\"2\"", "\"fee\":\"3\""))
            .and_then(|other| predicate::verify(&verifier(), &other.claim, &proof))
            .is_err()
    );
    assert!(predicate::transition_claim(&spec.replace("\"field\":0", "\"field\":9")).is_err());
}
