//! Backend-neutral public formats and policy. No cryptography is implemented here.
mod backend;
mod circuit;
mod error;
mod format;
mod inputs;
mod keys;
mod policy;
mod proof;

use sha2::{Digest, Sha256};

pub use backend::Backend;
pub use circuit::{CompiledCircuit, MAX_CIRCUIT_BYTES};
pub use error::{Result, ZkError};
pub use format::{decode_artifact, encode_artifact, MAX_ARTIFACT_BYTES};
pub use inputs::{PrivateInputs, PublicInputs, MAX_PUBLIC_INPUTS_BYTES, MAX_WITNESS_BYTES};
pub use keys::{
    KeyBinding, KeyPair, ProvingKey, VerifyingKey, MAX_PROVING_KEY_BYTES, MAX_VERIFYING_KEY_BYTES,
};
pub use policy::{Capabilities, SecurityPolicy, Soundness};
pub use proof::{Inspect, Phase, Proof, ProofMetadata, ProveOutput, MAX_PROOF_BYTES};

pub const FORMAT_VERSION: u16 = 2;

/// Domain-separated, length-prefixed SHA-256.
pub fn digest(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Capabilities {
        Capabilities {
            backend: "test".into(),
            backend_version: "1".into(),
            min_bits: 80,
            max_bits: 123,
            soundness: vec![Soundness::JohnsonBound],
            full_zero_knowledge: true,
        }
    }

    fn pair(bits: u16, vk: u8) -> KeyPair {
        let policy = SecurityPolicy {
            bits,
            ..SecurityPolicy::default()
        };
        KeyPair::new(&caps(), policy, [4; 32], vec![1], vec![vk]).unwrap()
    }

    fn inputs(byte: u8) -> PublicInputs {
        PublicInputs::from_bytes(vec![byte]).unwrap()
    }

    #[test]
    fn reject_non_r1cs() {
        assert!(CompiledCircuit::from_r1cs(b"fake".to_vec()).is_err());
    }

    #[test]
    fn reject_substituted_public_claim() {
        let kp = pair(116, 2);
        let p = Proof::new(&kp.proving, vec![3], inputs(5)).unwrap();
        assert!(p.validate_against(&kp.verifying, &inputs(6)).is_err());
        assert!(p.validate_against(&kp.verifying, &inputs(5)).is_ok());
    }

    #[test]
    fn reject_substituted_key() {
        let (kp, other) = (pair(116, 2), pair(116, 8));
        let p = Proof::new(&kp.proving, vec![3], inputs(5)).unwrap();
        assert!(p.validate_against(&other.verifying, &inputs(5)).is_err());
    }

    #[test]
    fn proof_is_bound_to_security_policy() {
        let (kp, other) = (pair(116, 2), pair(100, 2));
        let p = Proof::new(&kp.proving, vec![3], inputs(5)).unwrap();
        assert_ne!(kp.verifying.fingerprint(), other.verifying.fingerprint());
        assert!(p.validate_against(&other.verifying, &inputs(5)).is_err());
    }

    #[test]
    fn corrupted_verifying_key_is_rejected() {
        let mut bytes = encode_artifact(&pair(116, 2).verifying).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let vk: VerifyingKey = decode_artifact(&bytes).unwrap();
        assert!(vk.validate().is_err());
    }
}
