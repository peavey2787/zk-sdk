//! Real prove/verify through the linked upstream library. No mocks.
//! Vectors: `testdata/age_over` (age 20 > threshold 18, so public signals are [1, 18]).

use zk_core::{
    decode_artifact, encode_artifact, Backend, KeyPair, PrivateInputs, Proof, PublicInputs,
    SecurityPolicy, VerifyingKey, ZkError,
};
use zk_spartan_whir::SpartanWhir;

const R1CS: &[u8] = include_bytes!("../../../testdata/age_over/age_over.r1cs");
const WTNS: &[u8] = include_bytes!("../../../testdata/age_over/age_over.wtns");

struct Fixture {
    backend: SpartanWhir,
    keys: KeyPair,
    proof: Proof,
    expected: PublicInputs,
}

fn fixture(policy: SecurityPolicy) -> Fixture {
    let backend = SpartanWhir::new();
    let circuit = backend.compile(R1CS.to_vec()).expect("compile");
    let keys = backend.setup(&circuit, policy).expect("setup");
    let witness = PrivateInputs::from_wtns_bytes(WTNS.to_vec()).unwrap();
    let proof = backend.prove(&keys.proving, &witness).expect("prove").proof;
    let expected = backend.encode_public_inputs(&[1, 18]).unwrap();
    Fixture {
        backend,
        keys,
        proof,
        expected,
    }
}

#[test]
fn proves_and_verifies_at_default_policy() {
    let f = fixture(SecurityPolicy::default());
    f.backend
        .verify(&f.keys.verifying, &f.expected, &f.proof)
        .expect("valid proof verifies");
    assert_eq!(f.proof.claimed_public_inputs(), &f.expected);
}

#[test]
fn rejects_wrong_expected_public_inputs() {
    let f = fixture(SecurityPolicy::default());
    let wrong = f.backend.encode_public_inputs(&[1, 19]).unwrap();
    let result = f.backend.verify(&f.keys.verifying, &wrong, &f.proof);
    assert!(matches!(result, Err(ZkError::StatementMismatch)));
}

#[test]
fn rejects_corrupted_proof_via_real_verifier() {
    let f = fixture(SecurityPolicy::default());
    let mut bytes = encode_artifact(&f.proof).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x55;
    let verdict = decode_artifact::<Proof>(&bytes)
        .and_then(|p| f.backend.verify(&f.keys.verifying, &f.expected, &p));
    assert!(verdict.is_err());
}

#[test]
fn rejects_truncated_artifacts_and_foreign_key() {
    let f = fixture(SecurityPolicy::default());
    let vk = encode_artifact(&f.keys.verifying).unwrap();
    assert!(decode_artifact::<VerifyingKey>(&vk[..vk.len() - 1]).is_err());
    let other = fixture(SecurityPolicy {
        bits: 100,
        ..SecurityPolicy::default()
    });
    assert!(f
        .backend
        .verify(&other.keys.verifying, &f.expected, &f.proof)
        .is_err());
}

#[test]
fn rejects_unsupported_security() {
    let backend = SpartanWhir::new();
    let circuit = backend.compile(R1CS.to_vec()).unwrap();
    for bits in [0u16, 99, 119, 128] {
        let policy = SecurityPolicy {
            bits,
            ..SecurityPolicy::default()
        };
        assert!(backend.setup(&circuit, policy).is_err(), "{bits} bits");
    }
    let no_zk = SecurityPolicy {
        full_zero_knowledge: false,
        ..SecurityPolicy::default()
    };
    assert!(backend.setup(&circuit, no_zk).is_err());
}

#[test]
fn rejects_wrong_witness() {
    let backend = SpartanWhir::new();
    let circuit = backend.compile(R1CS.to_vec()).unwrap();
    let keys = backend.setup(&circuit, SecurityPolicy::default()).unwrap();
    let mut bad = WTNS.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let witness = PrivateInputs::from_wtns_bytes(bad).unwrap();
    assert!(backend.prove(&keys.proving, &witness).is_err());
}
