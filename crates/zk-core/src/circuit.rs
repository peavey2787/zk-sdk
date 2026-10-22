//! A compiled circuit: canonical R1CS bytes plus a content-derived identity.

use serde::{Deserialize, Serialize};

use crate::{digest, Result, ZkError, FORMAT_VERSION};

pub const MAX_CIRCUIT_BYTES: u64 = 512 * 1024 * 1024;
const CIRCUIT_DOMAIN: &[u8] = b"zk-sdk/circuit/v2";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledCircuit {
    version: u16,
    r1cs: Vec<u8>,
    program_id: [u8; 32],
}

fn well_formed(r1cs: &[u8]) -> bool {
    r1cs.len() >= 12 && r1cs.len() as u64 <= MAX_CIRCUIT_BYTES && r1cs.starts_with(b"r1cs")
}

impl CompiledCircuit {
    /// Wrap R1CS bytes. Only framing is checked here; the backend parses the relation.
    pub fn from_r1cs(r1cs: Vec<u8>) -> Result<Self> {
        if !well_formed(&r1cs) {
            return Err(ZkError::Format("invalid R1CS magic/size".into()));
        }
        Ok(Self {
            version: FORMAT_VERSION,
            program_id: digest(CIRCUIT_DOMAIN, &r1cs),
            r1cs,
        })
    }

    pub fn program_id(&self) -> [u8; 32] {
        self.program_id
    }

    pub fn r1cs(&self) -> &[u8] {
        &self.r1cs
    }

    pub fn validate(&self) -> Result<()> {
        if !well_formed(&self.r1cs)
            || self.version != FORMAT_VERSION
            || digest(CIRCUIT_DOMAIN, &self.r1cs) != self.program_id
        {
            return Err(ZkError::Format("circuit ID/version mismatch".into()));
        }
        Ok(())
    }
}
