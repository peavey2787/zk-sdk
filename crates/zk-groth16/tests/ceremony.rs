//! Trusted setups end to end on ephemeral keys from the published phase 1: sequential contributions
//! with a verifiable transcript, deterministic beacons, proofs that verify only under the setup the
//! verifier authorized, and rejection of damaged, foreign, uncontributed or mislabelled keys.

mod common;

use std::sync::Arc;

use zk_groth16::{
    commit, random_scalar, Beacon, Contribution, FieldInputs, Fr, Groth16Error, KeyPack, Phase1,
    Setup, Trust,
};

const CIRCUIT: &str = "open_32";

fn named(name: &str) -> Contribution {
    Contribution::Random {
        name: Some(name.to_owned()),
    }
}

fn beacon(name: &str) -> Contribution {
    Contribution::Beacon {
        name: Some(name.to_owned()),
        beacon: Beacon::new(vec![0x5a; 32], 10).unwrap(),
    }
}

fn contribute(pack: &KeyPack, contribution: &Contribution) -> KeyPack {
    common::ceremony()
        .contribute(pack, contribution, &mut |_, _, _| {})
        .unwrap()
}

/// A true `open_32` statement: the opening of a fresh commitment to 7.
fn inputs() -> FieldInputs<zk_groth16::Bn254> {
    let limbs = [7u16, 0];
    let blinding = random_scalar().unwrap();
    let mut inputs = FieldInputs::<zk_groth16::Bn254>::new();
    inputs.insert("commitment[0]".into(), commit(false, &limbs, blinding));
    inputs.insert("signed".into(), Fr::from(0u64));
    inputs.insert("limb[0]".into(), Fr::from(limbs[0]));
    inputs.insert("limb[1]".into(), Fr::from(limbs[1]));
    inputs.insert("blinding[0]".into(), blinding);
    inputs
}

fn verifies(setup: &Setup, public: &[Fr], proof: &[u8]) -> bool {
    setup
        .verifying_key(CIRCUIT)
        .is_ok_and(|vk| vk.verify(public, proof).is_ok())
}

#[test]
fn contributions_chain_into_a_verifiable_transcript() {
    let first = common::create(&[CIRCUIT], "alice");
    let second = contribute(&first, &named("bob"));
    let last = contribute(&second, &beacon("final"));
    let ids = [&first, &second, &last].map(|p| p.setup_id().unwrap());
    assert!(
        ids[0] != ids[1] && ids[1] != ids[2],
        "each contribution is a new setup"
    );

    let report = common::ceremony().verify(&last, &mut |_, _, _| {}).unwrap();
    assert_eq!(report.setup_id, ids[2]);
    let [key] = report.keys.as_slice() else {
        panic!("one key")
    };
    assert_eq!(key.circuit, CIRCUIT);
    let names: Vec<_> = key
        .contributions
        .iter()
        .map(|c| c.name.as_deref())
        .collect();
    assert_eq!(names, [Some("alice"), Some("bob"), Some("final")]);
    assert!(key.contributions[..2].iter().all(|c| c.beacon.is_none()));
    let recorded = key.contributions[2].beacon.as_ref().unwrap();
    assert_eq!(
        (recorded.value.as_slice(), recorded.exponent),
        (&[0x5a; 32][..], 10)
    );
    assert_eq!(key.circuit_hash.len(), 128);
}

#[test]
fn a_beacon_contribution_is_reproducible_and_a_random_one_is_not() {
    let base = common::create(&[CIRCUIT], "base");
    assert_eq!(
        contribute(&base, &beacon("b")).to_bytes(),
        contribute(&base, &beacon("b")).to_bytes()
    );
    assert_ne!(
        contribute(&base, &named("r")).to_bytes(),
        contribute(&base, &named("r")).to_bytes()
    );
}

#[test]
fn proofs_verify_only_under_an_authorized_setup() {
    let mine = common::create(&[CIRCUIT], "mine");
    let theirs = common::create(&[CIRCUIT], "theirs");
    let key_id = common::ceremony()
        .verify_key(CIRCUIT, mine.get(CIRCUIT).unwrap())
        .unwrap()
        .key_id;

    let prover = common::trusted(mine.clone());
    let out = prover.circuit(CIRCUIT).unwrap().prove(&inputs()).unwrap();
    assert!(verifies(&prover, &out.public_signals, &out.proof));
    assert!(!verifies(
        &common::trusted(theirs),
        &out.public_signals,
        &out.proof
    ));

    let ceremony = common::ceremony().clone();
    let unauthorized = Setup::new(ceremony.clone(), mine.clone(), Trust::default()).unwrap();
    assert!(matches!(
        unauthorized.verifying_key(CIRCUIT),
        Err(Groth16Error::Untrusted(_))
    ));
    let by_key = Trust::parse(&format!("# one key only\n{key_id}\n")).unwrap();
    let by_key = Setup::new(ceremony, mine, by_key).unwrap();
    assert!(verifies(&by_key, &out.public_signals, &out.proof));
}

#[test]
fn damaged_foreign_and_uncontributed_keys_are_rejected() {
    let ceremony = common::ceremony();
    let pack = common::create(&[CIRCUIT, "open_64"], "honest");
    let key = pack.get(CIRCUIT).unwrap().to_vec();
    ceremony.verify_key(CIRCUIT, &key).unwrap();
    for at in [100, key.len() / 4, key.len() / 2, 3 * key.len() / 4] {
        let mut bad = key.clone();
        bad[at] ^= 1;
        assert!(ceremony.verify_key(CIRCUIT, &bad).is_err(), "byte {at}");
    }
    let initial = ceremony.initial_key(CIRCUIT).unwrap();
    assert!(
        ceremony.verify_key(CIRCUIT, &initial).is_err(),
        "no contribution"
    );
    let other = pack.get("open_64").unwrap();
    assert!(
        ceremony.verify_key(CIRCUIT, other).is_err(),
        "another circuit's key"
    );

    let mut mislabelled = KeyPack::default();
    mislabelled.insert(CIRCUIT, other.to_vec()).unwrap();
    let setup = common::trusted(mislabelled.clone());
    assert!(setup.circuit(CIRCUIT).is_err(), "proving refuses it too");
    assert!(ceremony
        .contribute(&mislabelled, &named("x"), &mut |_, _, _| {})
        .is_err());
    assert!(KeyPack::default().insert("not_a_circuit", key).is_err());
    let mut bytes = pack.to_bytes();
    bytes.truncate(bytes.len() - 1);
    assert!(KeyPack::from_bytes(&bytes).is_err());
}

#[test]
fn only_a_published_phase1_file_is_accepted() {
    let mut bytes = common::phase1_bytes();
    let at = bytes.len() / 2;
    bytes[at] ^= 1;
    assert!(Phase1::new(Arc::from(bytes)).is_err());
}
