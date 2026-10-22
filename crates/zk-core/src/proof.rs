//! Proof envelope. The envelope is only bookkeeping: acceptance always requires
//! the backend's real verifier to succeed.

use serde::{Deserialize, Serialize};

use crate::{
    KeyBinding, ProvingKey, PublicInputs, Result, SecurityPolicy, VerifyingKey, ZkError,
    FORMAT_VERSION,
};

pub const MAX_PROOF_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    version: u16,
    binding: KeyBinding,
    bytes: Vec<u8>,
    claimed_public_inputs: PublicInputs,
}

impl Proof {
    pub fn new(key: &ProvingKey, bytes: Vec<u8>, inputs: PublicInputs) -> Result<Self> {
        key.validate()?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_PROOF_BYTES {
            return Err(ZkError::Format("empty or oversized proof".into()));
        }
        Ok(Self {
            version: FORMAT_VERSION,
            binding: key.binding().clone(),
            bytes,
            claimed_public_inputs: inputs,
        })
    }

    /// Prover-supplied. Never authoritative.
    pub fn claimed_public_inputs(&self) -> &PublicInputs {
        &self.claimed_public_inputs
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn binding(&self) -> &KeyBinding {
        &self.binding
    }

    /// Cheap pre-checks before the real verifier runs.
    pub fn validate_against(&self, key: &VerifyingKey, expected: &PublicInputs) -> Result<()> {
        key.validate()?;
        let matches = self.version == FORMAT_VERSION
            && &self.binding == key.binding()
            && &self.claimed_public_inputs == expected
            && !self.bytes.is_empty()
            && self.bytes.len() as u64 <= MAX_PROOF_BYTES;
        if matches {
            Ok(())
        } else {
            Err(ZkError::StatementMismatch)
        }
    }
}

/// Wall-clock time of one stage inside `prove`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase {
    pub name: &'static str,
    pub micros: u64,
}

#[derive(Clone, Debug)]
pub struct ProveOutput {
    pub proof: Proof,
    /// Per-stage timings of this proof, in execution order.
    pub phases: Vec<Phase>,
    /// Comes from the prover and is not an independent source of truth.
    pub claimed_public_inputs: PublicInputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMetadata {
    pub backend: String,
    pub backend_version: String,
    pub policy: SecurityPolicy,
    pub program_id: [u8; 32],
    pub verifying_key_id: [u8; 32],
    pub proof_bytes: usize,
    pub claimed_public_input_bytes: usize,
    pub format_version: u16,
}

pub trait Inspect {
    fn inspect(&self) -> ProofMetadata;
}

impl Inspect for Proof {
    fn inspect(&self) -> ProofMetadata {
        ProofMetadata {
            backend: self.binding.backend.clone(),
            backend_version: self.binding.backend_version.clone(),
            policy: self.binding.policy,
            program_id: self.binding.program_id,
            verifying_key_id: self.binding.vk_id,
            proof_bytes: self.bytes.len(),
            claimed_public_input_bytes: self.claimed_public_inputs.bytes().len(),
            format_version: self.version,
        }
    }
}
